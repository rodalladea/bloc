# governance

bloc currently uses maintainer-led governance. Repository administrators appoint
maintainers and grant access according to sustained contributions and review
quality. No external foundation or steering committee is implied.

Routine decisions happen in issues and PRs. Significant architecture, protocol,
or compatibility decisions require a written proposal and an accepted ADR.
Maintainers seek consensus and document unresolved tradeoffs before deciding.
Contributors may ask for reconsideration with new evidence.

Maintainers review PRs, manage releases, maintain private security reporting,
and enforce the code of conduct. Conflicted maintainers recuse themselves from
conduct decisions. Release and repository administration permissions should be
limited to those who need them.

## Maintainer and ownership

Rodrigo Dalla Dea ([@rodalladea](https://github.com/rodalladea)) is the sole owner
and maintainer of [bloc](https://github.com/rodalladea/bloc). He owns review,
releases, security triage, and community moderation. Private contact:
[rodalladea@catap.io](mailto:rodalladea@catap.io).

All changes after the initial repository bootstrap go through a PR with passing
required checks and resolved review conversations. While the project has one
maintainer, zero approving reviews are required: Rodrigo reviews contributions
and may merge his own PRs after checking the diff and verification results.
CODEOWNERS records ownership without requiring self-approval. Require one
independent approving review when another active maintainer can provide it.

There is currently no independent conduct appeal reviewer. Do not promise an
independent review when the sole maintainer is involved in a report. Changes to
governance are proposed by PR.
