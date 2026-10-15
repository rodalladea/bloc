# development guidance

Read the root AGENTS.md first. Prefer the smallest complete change that fits the
current project stage. Do not create speculative crates, services, generic
provider interfaces, or fake protocol implementations.

## Layout

- `src/main.rs`: environment configuration, tracing, listener, shutdown.
- `src/lib.rs`: HTTP application, handlers, response policy.
- `templates/`: HTML; currently static and embedded at compile time.
- `assets/`: styles and pinned third-party browser assets.
- `tests/`: observable HTTP behavior.
- `docs/`: architecture, roadmap, decisions, and contributor/agent guidance.

As features grow, extract cohesive modules before considering workspace crates.
Keep protocol parsing and validation separate from application policy and storage.

## Behavior before implementation

Follow the [BDD workflow](../development-workflow.md). Read existing records in
`docs/behaviors/` before changing a capability; update its examples and test mapping
with the implementation. For unchanged behavior, preserve existing expectations.

## Code design and patterns

Keep functions and modules focused on one cohesive responsibility. Prefer clear
names, explicit control flow, small public APIs, and composition. Separate domain
rules from HTTP handling and external I/O as those responsibilities emerge; do
not generate empty layers to match an architecture diagram.

Choose a design pattern only when it solves a concrete problem in the current
feature. For example, an adapter can translate an external provider's data into
application types; a strategy can represent genuinely interchangeable policies.
Explain the problem and tradeoff in the PR, and use an ADR for significant boundary
changes. Do not introduce repositories, factories, or generic service abstractions
by default. Extract shared code when it represents the same rule, not merely
similar syntax; avoid both duplicated policy and premature generalization.

## Dependency injection

Pass dependencies explicitly through function parameters or constructors. Assemble
concrete implementations at application startup and pass the required state into
the application. Avoid hidden global dependencies and service locators. Keep
configuration and resource creation out of domain logic; pass validated settings
and already-created resources instead.

Start with concrete types. Introduce a small, purpose-specific trait when a boundary
needs substitution, such as storage, an external provider, or a clock used to test
expiry. Do not create a trait for every struct. Choose generics or trait objects
according to the actual dispatch and ownership needs; no dependency-injection
container is required. Give each component only the dependencies it needs rather
than passing the entire application state through every layer.

Make side effects explicit and isolate them so business rules can be tested
deterministically. Use test implementations at meaningful external boundaries,
and retain integration tests for real adapter behavior. Avoid mocks that merely
assert internal call sequences instead of observable outcomes.

## Rust practices

Use types to express domain distinctions and valid states. Prefer enums for
finite alternatives and validated constructors where invariants matter. Return
typed errors for expected failures and map them to public responses at the
boundary without exposing sensitive details. Avoid `unwrap` and `expect` on
fallible production paths; any invariant-based exception needs a clear rationale.

Keep ownership and borrowing straightforward. Use shared ownership and locks only
when resources genuinely need sharing, keep lock scopes short, and avoid holding
a lock across an await point. Keep blocking work off asynchronous request paths.
Do not add clones, concurrency, or caching to solve hypothetical performance
problems; use evidence and preserve correctness when optimizing.

Follow the pinned toolchain's formatter and lint checks. Document public contracts,
invariants, and surprising tradeoffs rather than narrating obvious code. Consult
current library documentation when selecting a library-specific implementation,
as required by AGENTS.md.

## HTMX practices (2.0.8)

bloc pins HTMX **2.0.8** in `assets/vendor/htmx-2.0.8.min.js`. Use the official
[2.0.8 documentation](https://github.com/bigskysoftware/htmx/blob/v2.0.8/www/content/docs.md)
and [swap reference](https://github.com/bigskysoftware/htmx/blob/v2.0.8/www/content/attributes/hx-swap.md),
not examples from another release. Context7 currently lacks a version-specific
2.0.8 entry; use these tagged sources when it cannot supply that version. Recheck
this guidance and the asset attribution when upgrading.

### Responses and navigation

Keep essential actions available through real links and forms. Return HTML for
HTMX updates. When one URL varies by `HX-Request`, send `Vary: HX-Request` and
configure `historyRestoreAsHxRequest: false`. History URLs must support full-page
requests, including refresh and history restoration.

Choose `hx-target` and `hx-swap` deliberately. Keep IDs unique and retain a usable
target after replacement. Test repeated interactions, not just the first swap.
Follow [DESIGN.md](../../DESIGN.md) for semantic controls, focus, labels, and
feedback; verify that updates preserve keyboard usability and announce relevant
status changes without excessive live-region output.

### Errors and request behavior

HTMX 2.0.8 does not swap 4xx/5xx responses by default. Define explicit handling for
validation responses such as 422; do not enable swapping every error response.
Keep server-side validation authoritative. Show useful loading, validation, and
network-failure feedback, and allow users to recover without losing safe input.
Never refill secret fields or expose internal errors in a fragment.

For each new interaction, decide how repeated submissions and overlapping
requests should behave. Prevent stale results from replacing newer ones, and
enforce correctness on the server even when browser controls are bypassed.

### Security and configuration

Preserve the existing `htmx-config` in `templates/index.html`: `allowEval: false`,
`allowScriptTags: false`, `selfRequestsOnly: true`, `historyCacheSize: 0`, and
`includeIndicatorStyles: false`. Keep required scripts and indicator styles in
local assets compatible with the current CSP. Do not weaken these settings to
copy an example. Review security implications before changing them.

History snapshots are already disabled globally in bloc. Keep sensitive pages
out of HTMX history storage if navigation changes. Follow the
[security requirements](../security.md) for auto-escaping, CSRF, authorization,
and secret handling on both full-page and fragment endpoints. Client attributes
and HTMX request headers cannot grant permissions.

### Verification

Use BDD examples for normal and enhanced flows, failed validation, and permission
denial when applicable. Test response status, headers, and fragment content in
the HTTP suite. Verify swaps, keyboard focus, loading/error feedback, and browser
navigation in a browser; HTTP tests alone do not exercise HTMX. Record manual
checks and remaining automation gaps in the behavior record or handoff. These
are requirements for future interactions, not claims about implemented identity
flows or existing browser-test coverage.

## Implementation

Use typed errors and validate configuration at startup. Do not panic on user input.
Never interpolate untrusted strings into HTML; introduce an auto-escaping template
engine when dynamic content is needed. Keep JavaScript local, preserve semantic
HTML and keyboard access, and provide normal links/forms for essential flows.
HTMX endpoints return HTML fragments; do not expose secrets through fragments.

Choose maintained dependencies intentionally. Consult current documentation and
explain additions. Keep Cargo.lock committed. Update vendored assets with their
license, source, version, and checksum; never edit their contents directly.

Run the README checks. Add tests for changed behavior and meaningful failure
cases, especially security boundaries. Avoid tests that only repeat implementation.
Document new configuration and update the roadmap when capabilities actually ship.
