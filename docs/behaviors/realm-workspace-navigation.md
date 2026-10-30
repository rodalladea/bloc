# Realm workspace navigation

Status: implemented (maintainer request, 2026-10-29).

The administrator works primarily with users. The realm is persistent navigation
context, not a settings screen that must be traversed to reach those users.
Installation administration remains explicitly available in the workspace menu.
No new permissions, identity aggregation, search, metrics or storage migration.

## Examples

- **workspace-entry:** Given no realms, when opening `/admin`, then open the
  realm list with its create action. Given exactly one realm and no valid saved
  preference, open that realm's users. Given multiple realms and no valid saved
  preference, open the realm list with direct Users, Settings and Authentication
  links. An explicit installation link always opens installation details.
- **workspace-return:** Given an authorized visit to a realm, when returning to
  `/admin` in the same browser, then open that realm's users. A missing or malformed
  saved ID falls back to the zero/one/multiple rule. Suspended realms remain
  administrable and their status is visible. The preference is a navigation hint,
  never authority; all reads still recheck the installation administrator session.
- **workspace-switch:** Given any administrator workspace, when opening the menu,
  then offer realm choices by name and immutable ID (names may repeat), plus
  installation, all realms and create realm. Selecting a realm opens its users;
  its sidebar exposes Users, Settings and Authentication. A bounded first page
  of at most 50 choices links to the paginated realm list for all remaining realms.
- **workspace-context:** Given a realm's users, user details, settings or
  authentication screen, when navigating or changing context, then the sidebar
  identifies the current realm and correct active section. Context-changing
  navigation loads the full page so enhanced fragments cannot leave a stale shell.
  Ordinary links work without JavaScript, including mobile navigation.

## Verification

`tests/realm_user_management.rs::directory_workspace_navigation` covers entry,
return, invalid preferences and expired authority through real HTTP handlers.
`src/workspace.rs::tests::preference_accepts_only_one_realm_id` covers malformed
and duplicate preference cookies. `tests/realm_user_management.rs::directory_browser_workspace`
(`tests/support/workspace_browser.py::verify`) covers switching between duplicate
names, all three direct realm-list actions, active navigation on user details and
access-link screens, explicit installation access, back/forward history, mobile
navigation, no-JavaScript navigation, and the 50-choice selector/paginated list.

The HTTP proof first failed with the original entry returning 200 instead of the
new 303. Verification uses synthetic accounts in disposable TLS database fixtures;
it does not establish production authentication acceptance or capacity.


Verification passed on PostgreSQL 17.11 and 18.6: all 41 directory proofs, the
workspace browser proof, six administrator regressions and realm-authentication
C01/C09. Formatting, ordinary all-target tests, Clippy with warnings denied,
documentation generation and documentation mapping checks passed. Evidence:
[projects/bloc/.checks/realm-workspace-navigation-2026-10-29.zip](https://drive.catap.io/s/24c13732f9478655a99ae9cd3eac7dcbdf7ece27d9edd394?file=86d403c496e03dce2ed6ebacc86954fa7f0d137e7b88e38d).
