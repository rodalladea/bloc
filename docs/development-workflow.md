# behavior-driven development

bloc uses behavior-driven development (BDD) to discover, describe, and verify
features through concrete examples. Start with the problem and observable
outcomes before choosing an implementation. BDD is a collaboration practice,
not a requirement to install a Gherkin runner or write every test in prose.

## Discover the behavior

Read the [agent index](../AGENTS.md), [current capabilities](../README.md),
[architecture](architecture.md), and [roadmap](roadmap.md). Follow the relevant
design and security guidance. Identify the actor, their problem, the intended
outcome, and the smallest useful scope. Record what is explicitly out of scope.
For a new feature, explain why it belongs in bloc and how it fits the roadmap;
a roadmap entry alone does not authorize implementation.

Explore rules with concrete examples, including success, meaningful rejection,
and boundary cases. Record unresolved questions and assumptions. Ask the requester
or maintainer when an answer changes scope, observable behavior, or a security
policy; continue independent work while awaiting an answer. Agents may resolve
routine implementation details within the authorized scope, but must not invent
product requirements or treat their own proposal as maintainer approval.

For identity work, include the actor's permissions, realm and trust boundaries,
invalid or expired inputs, replay where relevant, and observable denial behavior.
Use synthetic data and follow [security requirements](security.md). Examples
supplement threat modeling and protocol conformance checks; they do not replace them.

## Describe the agreement

Create or update a focused Markdown record under `docs/behaviors/` using the
[template](behaviors/template.md). Use a descriptive filename and stable scenario
IDs, such as `provider-selection-01`. One record can cover a cohesive capability;
do not create a new document for every test. Small bug fixes can extend an existing
record. Documentation-only work and refactoring with unchanged behavior need no
new scenarios; say why in the handoff or PR.

Write examples in Given/When/Then form:

- **Given** the relevant starting context.
- **When** the actor takes an action or an event occurs.
- **Then** the observable result, including important effects that must not occur.

Use domain language, concrete inputs, and checkable results. Avoid vague outcomes
such as “works securely,” internal method calls, and incidental UI details. HTTP
status codes are appropriate when the HTTP interface itself is the contract.

Record the decision and its source: requester instruction, issue discussion, or
maintainer review. Separate proposed behavior from agreed behavior and shipped
behavior. Use `proposed`, `agreed`, `implemented`, or `superseded` as record status;
link the replacement for superseded records. Mixed delivery belongs in explicitly
marked scenario coverage rows, not an overall claim that everything works.

Significant architecture, protocol, dependency, storage, realm isolation, or compatibility
choices need a numbered ADR with context, options, decision, consequences, and
status. Link the behavior record and ADR in both directions. BDD explains what
outcome is needed; ADRs explain why a technical approach was chosen. Follow
[governance](../GOVERNANCE.md) for acceptance; do not silently rewrite accepted
historical decisions. Routine choices can stay in the issue or PR.

## Implement and verify

For each agreed behavior change, add or adapt an automated test at the lowest
layer that can demonstrate the observable outcome. Run it before implementation
and confirm it fails for the expected reason, then implement the smallest complete
change and refactor while keeping it passing. For a bug, first reproduce the
failure. Retrospective documentation of existing behavior may map existing tests;
label it as retrospective rather than claiming a test-first sequence.

Use the existing Rust test suite. Markdown scenarios are not executable and are
not automatically checked against tests. Do not add a BDD dependency or step
binding layer without a concrete need and a documented dependency decision.
Keep a coverage table linking every scenario ID to the test file and exact test
name, or a specific manual check and its result. One test may cover several
examples. Mark missing or partial coverage explicitly; manual checks need a reason
and must not substitute for automatable security assertions.

Run relevant [README checks](../README.md#development), inspect the diff, and
follow [review guidance](agents/review.md). Update behavior records, tests, and
capability documentation together when the contract changes. Record what was
actually verified and any limitations. Mark a record implemented only when its
agreed scope is implemented and verified; passing examples alone do not establish
production readiness or protocol compliance.

## Future agent handoff

For feature work, report the behavior record and scenario IDs, decision sources
and related ADRs, test results, and unresolved questions or coverage gaps. Do not
start deferred features merely to fill a template. A reviewer should be able to
trace the requested outcome through the examples to evidence in tests.

See the [scaffold HTTP record](behaviors/scaffold-http.md) for a retrospective
example using the tests already in this repository.
