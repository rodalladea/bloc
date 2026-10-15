# 0002: behavior-driven development workflow

Status: accepted

## Context

bloc has a scaffold, a roadmap, and agent guidance. Future contributors and agents
need a consistent way to turn feature requests into explicit behavior, preserve
decision context, and distinguish proposed capabilities from working ones. The
repository owner requested adoption of BDD as the development workflow.

## Decision

Adopt the [BDD workflow](../development-workflow.md): discover rules and examples,
describe agreed behavior, then implement and verify it. Store durable behavior
records in `docs/behaviors/`, with stable scenario IDs and explicit test mappings.
Use the [scaffold record](../behaviors/scaffold-http.md) as a retrospective example.

Keep significant technical choices in ADRs under the existing governance model.
Feature proposals do not authorize themselves, and an agent must not invent
maintainer acceptance. Keep proposed, agreed, and implemented behavior distinct.

Use Markdown Given/When/Then examples and the existing Rust tests initially.
An executable Gherkin framework is deferred until its benefits justify its
additional dependencies and maintenance. Informal PR-only examples were also
considered, but durable records make feature context easier for future agents to find.

## Consequences

Behavior records, tests, and capability documentation must evolve together.
Reviewers manually check scenario-to-test mappings; CI still executes Rust tests,
not Markdown scenarios. Small fixes can extend existing records, and changes that
do not affect behavior need no new record. BDD does not replace security review,
threat modeling, or protocol conformance validation.
