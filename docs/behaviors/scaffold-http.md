# scaffold HTTP behavior

Status: implemented

This is a retrospective record of the existing scaffold, not a new feature or a
claim that its implementation followed a test-first process.

## Problem and scope

A developer needs to inspect the running scaffold and check process liveness.
The foundation milestone includes local pages, assets, and a status fragment.
Authentication, readiness checks, token issuance, and federation are out of scope.

## Rules and decisions

The existing [foundation ADR](../adr/0001-foundation.md) records the stack and
scaffold scope. The [README](../../README.md) distinguishes implemented HTTP
behavior from planned identity functionality. This record documents those existing
choices; it does not authorize additional endpoints or identity features.

## Open questions and assumptions

None for these existing examples. Future identity endpoints will require new
behavior agreements and revision of the corresponding absence checks.

## Scenarios

### scaffold-http-01: inspect available scaffold resources

Given the scaffold application
When a developer requests each resource below with GET
Then each response has status 200 and the listed content type and body content
And each response has Cache-Control `no-store`
And its Content-Security-Policy contains `frame-ancestors 'none'`

| Resource | Content type starts with | Body contains |
| --- | --- | --- |
| `/` | `text/html` | `Authentication, token issuance` |
| `/healthz` | `text/plain` | `ok` followed by a newline |
| `/fragments/status` | `text/html` | `role="status"` |
| `/assets/app.css` | `text/css` | `:root` |
| `/assets/htmx.min.js` | `text/javascript` | `htmx` |

The liveness response says nothing about dependency readiness or identity safety.
These checks verify HTTP responses, not browser interaction or accessibility.

### scaffold-http-02: reject requests for absent endpoints

Given the scaffold with identity protocols unimplemented
When a client sends GET to each of `/.well-known/openid-configuration`,
`/oauth/token`, `/saml`, and `/missing`
Then each response has status 404
And each response has X-Content-Type-Options `nosniff`

These examples concern these GET requests only; they are not protocol conformance
checks or an exhaustive inventory of unsupported paths and methods.

## Verification

| Scenario | Delivery / coverage | Evidence |
| --- | --- | --- |
| scaffold-http-01 | Implemented / automated | [tests/http.rs](../../tests/http.rs): `serves_local_assets_health_and_htmx_fragment` |
| scaffold-http-02 | Implemented / automated | [tests/http.rs](../../tests/http.rs): `unimplemented_protocol_endpoints_are_not_exposed` |

Run the existing suite with `cargo test --locked --all-targets`. Per-change test
results belong in the PR or handoff; the mapping above is not a CI execution log.
