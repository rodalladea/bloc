# administrator dashboard interface

Status: implemented

## Problem and scope

The installation administrator needs a coherent workspace for bloc's current
capabilities. Account details and directory actions previously appeared in separate,
loosely organized layouts. The requester asked on 2026-10-23 for a usable dashboard
inspired by Supabase, preserving bloc's colors without copying its interface.

In scope: shared navigation, overview action hierarchy, directory and account
layout, responsive behavior, keyboard access, and existing form flows. Out of
scope: new identity capabilities, metrics, search, database changes, deployment,
and changes to authorization or session policy.

## Rules and decisions

The requester instruction establishes the redesign scope. [DESIGN.md](../../DESIGN.md)
records the resulting layout direction. [ADR 0001](../adr/0001-foundation.md) and
existing administrator/directory boundaries remain unchanged; no new dependency
or architecture decision is needed. All navigation uses existing real routes.
HTMX still replaces only the main content. Public access forms remain focused.
Directory users and planned protocols must not appear to support authentication.
The requester's follow-up on 2026-10-23 removes the duplicated header path;
breadcrumbs remain only inside the specific page.

## Open questions and assumptions

None blocking. Use only existing data and actions; do not add dashboard metrics
or future-feature navigation to fill space.

## Scenarios

### dashboard-01: find the next action

Given an authenticated installation administrator
When they open the overview
Then they can create a tenant, browse tenants, change their password, and sign out
And installation/account information is grouped separately from directory work
And directory users are explicitly described as unable to sign in.

### dashboard-02: navigate consistently

Given the administrator is viewing a directory or account security
When they navigate or submit an enhanced form
Then one navigation shell remains, indicating the current section
And a tenant's user directory is reachable from its page header
And the main content and its feedback remain keyboard accessible
And public sign-in, setup, and recovery forms do not show workspace navigation.

### dashboard-03: use small screens and fallback forms

Given a desktop or narrow viewport, with or without JavaScript
When the administrator navigates, edits records, or submits an invalid form
Then navigation remains available, the page does not overflow horizontally,
tables scroll within their container, and actions remain reachable
And existing validation, confirmation, recovery, and session behavior is preserved.

## Verification

The captures and checks below describe the initial dashboard revision. The later
[portable interface refinement](portable-interface.md) replaces its visual shell
with one theme-integrated menu and compact settings rows; the functional scenarios
in this record remain applicable.

| Scenario | Delivery / coverage | Evidence |
| --- | --- | --- |
| dashboard-01 | Implemented; verified on PostgreSQL 17 and 18 | `src/administrator_tests.rs`: `dashboard_navigation_and_actions`; `tests/administrator_access.rs`: `administration_home`, `browser_preview`; manual overview visual review at 1280px and 375px |
| dashboard-02 | Implemented; verified on PostgreSQL 17 and 18 | `dashboard_navigation_stays_out_of_public_access_forms`; `tests/administrator_access.rs`: `browser_preview`; `tests/tenant_user_management.rs`: `directory_browser_interactions`, `directory_screen_t3` |
| dashboard-03 | Implemented; verified on PostgreSQL 17 and 18 | `tests/administrator_access.rs`: `browser_preview`, `browser_no_javascript`, `browser_validation`, `browser_loading_network`, `browser_session_expiry`; `tests/tenant_user_management.rs`: `directory_screen_t1`, `directory_screen_t2`, `directory_screen_t3`, `directory_screen_u1`, `directory_screen_u2`, `directory_screen_u3`, `directory_browser_interactions` |

The two dashboard render tests failed against the original interface before the
implementation, then passed. Browser expectations were updated for the new layout;
existing mutation, validation, security, and no-JavaScript assertions are retained.

Initial redesign previews, before the header-path removal, use synthetic data
and are retained outside the repository:

- `projects/bloc/.design/dashboard-interface-2026-10-23/overview-desktop.png` — [desktop overview](https://drive.catap.io/s/24c13732f9478655a99ae9cd3eac7dcbdf7ece27d9edd394?file=52f2f97d85a406adda34695a44a2758f153ac68345c4d39d).
- `projects/bloc/.design/dashboard-interface-2026-10-23/overview-mobile.png` — [mobile overview](https://drive.catap.io/s/24c13732f9478655a99ae9cd3eac7dcbdf7ece27d9edd394?file=63cb2fe73fbae10b70718e1ffd0df591362823605a2088cb).
- `projects/bloc/.design/dashboard-interface-2026-10-23/tenant-details-desktop.png` — [tenant details](https://drive.catap.io/s/24c13732f9478655a99ae9cd3eac7dcbdf7ece27d9edd394?file=6ece75c4aa132ed02694f37d964da3204b969df73c2b7a65).

Initial dashboard validation on 2026-10-23: formatting, strict Clippy, all-target ordinary tests,
and documentation build passed. The storage runner passed 128 regression checks
on each of PostgreSQL 17.11 and 18.6, including all twelve browser proofs per major.
Manual review covered overview, account security, empty tenants, tenant details,
and user details at desktop and mobile sizes. The native service-capacity proof
was excluded by the standard runner; no capacity or production-readiness claim is
part of this interface change.

Evidence under `projects/bloc/.design/dashboard-interface-2026-10-23/`:

- `ordinary.txt` — [ordinary test results](https://drive.catap.io/s/24c13732f9478655a99ae9cd3eac7dcbdf7ece27d9edd394?file=77136c186bfda06485a1765915fb53aded475c3f9fe212ab).
- `postgres-17.txt` — [PostgreSQL 17 results](https://drive.catap.io/s/24c13732f9478655a99ae9cd3eac7dcbdf7ece27d9edd394?file=de7f97279b3997aeda9bc81ed24423203459561103889e77).
- `postgres-18.txt` — [PostgreSQL 18 results](https://drive.catap.io/s/24c13732f9478655a99ae9cd3eac7dcbdf7ece27d9edd394?file=e30357e6e08d249a0a3f7be2e53f83b1d426d8abf7cc9901).

## Mobile menu refinement — 2026-10-24

Decision source: the requester asked to replace the dashboard mobile menu with a
hamburger icon that opens the menu. No route, authority, or dependency changes.

### dashboard-04: open mobile navigation

Given an administrator on a viewport narrower than 640px with JavaScript enabled
When they activate the hamburger button using a pointer or keyboard
Then a left drawer slides over the content with the desktop navigation groups
and utility controls, while the bloc dropdown sits beside the hamburger in the header
And a dimmed backdrop and close button dismiss the drawer
And keyboard focus stays inside the drawer and background content is inert
And reduced-motion preferences disable animation
And the button exposes whether navigation is expanded
And Escape closes navigation and returns focus to the button
And clicking outside closes navigation
And desktop navigation is always visible, with the hamburger hidden
And without JavaScript the navigation remains expanded and usable.

Verification: `python3 tests/support/mobile_menu_browser.py` passed in Chromium.
The focused proof renders the actual sidebar template and application assets
with synthetic values and checks mobile keyboard interaction, expanded state,
Escape/focus, backdrop dismissal, focus containment, link dismissal, desktop resizing and the
no-JavaScript fallback.
It failed before implementation because the hamburger control was missing.
This checks the isolated shell, not authenticated service or HTMX form flows.
Rust build, lint, ordinary tests and documentation checks could not run in the
editing environment because the Rust toolchain is unavailable.
