# review and handoff guidance

Before handoff, inspect the diff for unrelated edits, secrets, misleading feature
claims, dependency changes, and generated files. Run the relevant README checks
and report exactly what passed and what could not run.

For behavior changes, follow the [BDD workflow](../development-workflow.md): check
that examples match the agreed scope, scenario IDs map to actual assertions, and
missing coverage and unresolved decisions are explicit. Check the decision source
and related ADRs; do not equate a proposed feature with an accepted one. Changes
without behavioral impact may state that instead of adding scenarios.

For identity changes, review failure behavior and cross-realm access as carefully
as the successful path. Check documentation against actual implementation.

Review code against the [design and dependency guidance](development.md#code-design-and-patterns):
responsibilities are cohesive, dependencies are explicit, abstractions solve a
present need, and tests verify outcomes. Check error handling and ownership where
relevant; do not require new layers or traits merely to satisfy a pattern.

For HTMX changes, use the [2.0.8 guidance](development.md#htmx-practices-208).
Check fallback behavior, fragment errors, browser navigation and focus, and
preservation of the existing security configuration. Distinguish HTTP-test
evidence from browser checks.

Use Conventional Commit subjects when asked to commit. PR titles follow the same
format; use the PR template, explain the user-visible result and validation, and
identify migrations or security implications. See CONTRIBUTING.md for details.

Keep AGENTS.md an index. Update linked guidance when architecture or commands
change instead of copying instructions into several tool-specific files.

The final handoff should state what changed, how it was checked, and remaining
limitations. Never claim to have configured remote repository settings unless
those settings were actually changed and verified.
