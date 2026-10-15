# contributing to bloc

Contributions are welcome. Read the [code of conduct](CODE_OF_CONDUCT.md),
[README](README.md), and [architecture](docs/architecture.md) first. Discuss large
features or protocol decisions in an issue before implementing them. Small fixes
can go straight to a pull request. Report vulnerabilities privately as described
in [SECURITY.md](SECURITY.md).

## Workflow

1. Fork the repository and create a focused branch, such as `feat/provider-catalog`
   or `fix/health-response`.
2. Install the pinned Rust toolchain and run `cargo run --locked`.
3. Follow the [BDD workflow](docs/development-workflow.md): clarify the problem,
   record concrete behavior examples and decisions, then implement a scoped change
   with tests mapped to those examples. Changes without behavioral impact need no
   new behavior record.
4. Run the four checks in the README. Do not commit `target/`, secrets, or local
   configuration. Commit Cargo.lock changes when dependencies change.
5. Open a PR using the template. Explain the problem, result, and verification.

No contributor license agreement or sign-off is currently required. By submitting
work, you agree to license it under Apache-2.0 and confirm you have the right to
contribute it. Keep third-party attribution intact.

## Commit messages and PR titles

Use Conventional Commits:

```text
feat(providers): add provider configuration validation
fix(http): reject invalid bind addresses
docs: clarify the development setup
```

Types: `feat`, `fix`, `docs`, `refactor`, `perf`, `test`, `build`, `ci`, `chore`,
`revert`. A scope is optional. Use an imperative, concise description. Mark
breaking changes with `!` and explain them in a `BREAKING CHANGE:` footer. Keep
commits focused; use the body to explain motivation when it is not obvious.

Maintainers squash merge PRs, so the PR title becomes the final commit subject.
CI checks the title. Local hooks are optional; validation must not depend on them.

## Review expectations

Rodrigo Dalla Dea (@rodalladea) reviews contributions before merging. While he is
the sole maintainer, his own PRs require passing checks and a self-review, but no
independent approval; see [governance](GOVERNANCE.md). Identity and authorization changes
need explicit security review, documented trust boundaries, and negative tests.
Explain dependency additions. Avoid hand-written protocol and cryptography code.
Keep UI semantic and accessible, and retain normal navigation where possible.

Update the Unreleased changelog for user-visible changes. Architecture decisions
belong in numbered records under `docs/adr/`. Tests must pass before merge;
maintainers configure required checks using [the repository checklist](docs/releases.md).
