# Portable interface and workspace redesign

Status: implemented

## Decision and scope

The requester asked on 2026-10-23 to redesign all existing screens, retain only
bloc's colours as a visual constraint, and follow the actual interfaces of
Cursor, Supabase, and Slack more closely. They confirmed light/dark themes,
system preference plus a manual choice, and reusable styles and interactions
that can later move to a CDN and work with ordinary HTML. The earlier discovery
preview was rejected as too similar to the existing interface.

The requester subsequently supplied a Supabase settings screenshot and explicitly
rejected the black rail, “b” icon and duplicate navigation. The design now uses
one theme-integrated menu, compact controls, bordered settings rows, integrated
tables and focused access forms. The full-width context header from that revision
was subsequently removed by the sidebar structure refinement below.
Their next refinement softens resting field borders and separators in both themes
and removes the active navigation dot and outline. The neutral selection fill,
layout, focus indicators and validation states remain. This is a visual-only
change to interface-05; it adds no application behavior.
The latest supplied button/input references supersede the initial control
styling: 30px desktop buttons, 32px fields, 12px control corners, cool neutral
surfaces and more visible control borders. Field focus uses a 3px ring in the
focused border's hue at 24% opacity instead of the green outline/halo; touch
shared button/input minimum heights remain 44px. Application operations and the page layout are unchanged.
The requester subsequently approved the light theme but rejected the blue cast
of dark controls alongside the green badges. Seven dark colour tokens now use
the workspace's graphite/zinc family; all light values, geometry and tag colours
are preserved.
The final rounding pass unifies bounded components on the shared 12px radius:
navigation items, panels, notices, badges, tiles, icon containers and standalone
table wrappers now match controls. Circles remain circles and unboxed layout
sections retain straight separators. This is a visual-only token consolidation.
The reusable assets stay in this repository. Publication, new identity features,
new data operations, and changes to authentication policy are out of scope.
Existing dashboard and directory behavior records still govern their flows.

## Scenarios

### interface-01: choose an appearance

Given a browser with no saved appearance choice
When an administrator opens an access or workspace screen
Then the interface follows the system light/dark preference
And selecting Light or Dark overrides that preference across navigation and reload
And selecting System restores system tracking.

### interface-02: preserve usable fallback

Given browser storage is unavailable or JavaScript is disabled
When an administrator opens or submits an existing screen
Then the page and ordinary links/forms remain usable
And system appearance still works without JavaScript
And a failed preference-storage write does not break the current appearance choice.

### interface-03: keep the workspace usable

Given any current screen at a desktop or narrow viewport
When the administrator navigates, edits a record, or receives an error
Then navigation and actions remain reachable, keyboard focus is visible,
and content stays within the viewport apart from contained table scrolling
And existing confirmation, validation, expiry and recovery behavior is preserved.

### interface-04: consume the same interface assets elsewhere

Given an ordinary HTML document without Rust or HTMX
When it loads the reusable stylesheet and script and opts into the UI scope
Then its controls and appearance selection work using the same assets as bloc
And unrelated content outside that scope is not restyled
And no bloc route or server request is required by the reusable runtime.

### interface-05: use one compact navigation and settings surface

Given the administrator opens a workspace page
When viewing it on desktop or a narrow screen
Then one labeled Administration menu exposes overview, tenants and account security
And there is no separate black rail or “b” icon
And desktop buttons and fields are compact, while their shared minimum-height
tokens become 44px on narrow viewports and coarse pointers
And directory record links retain an independent 28px minimum height
And focused fields have a neutral border and a translucent ring in the same hue
And keyboard focus on links and buttons remains outlined, while forced-colours
mode also supplies an outline for fields.

The layout refinement is visual; existing authentication and directory operations
retain their contracts. Existing browser layout assertions are adapted to the
new composition; this is not a claim of test-first implementation.

## Verification

| Scenario | Evidence | Status |
| --- | --- | --- |
| interface-01 | `interface_theme_picker_is_only_available_inside_the_application`; browser appearance checks | Passed on PostgreSQL 17 |
| interface-02 | Existing no-JavaScript and form regression checks; storage-denied appearance check | Passed on PostgreSQL 17 |
| interface-03 | Existing administrator and directory browser checks plus visual review | Passed on PostgreSQL 17 |
| interface-04 | Standalone consumer browser check | Passed on PostgreSQL 17 |
| interface-05 | `control_density`, standalone field-focus checks, `browser_preview`, directory layout checks and visual review | Passed on PostgreSQL 17 |

## Visual evidence

Real-browser captures use synthetic data and are retained in
`projects/bloc/.design/supabase-interface-2026-10-23/`:

- `admin-password-dark-1280.png` — [dark desktop settings](https://drive.catap.io/s/24c13732f9478655a99ae9cd3eac7dcbdf7ece27d9edd394?file=c52cc6f19d3886a3423ee485c6846680529622d36d378b43).
- `admin-password-1280.png` — [light desktop settings](https://drive.catap.io/s/24c13732f9478655a99ae9cd3eac7dcbdf7ece27d9edd394?file=295ea3949d837979a8ac6d82340870b5902d64c42ee7a869).
- `admin-password-dark-375.png` — [mobile settings](https://drive.catap.io/s/24c13732f9478655a99ae9cd3eac7dcbdf7ece27d9edd394?file=78aaa54657fc88061e181fe081222c51be1c8cadc4b97a7b).
- `admin-admin-dark-1280.png` — [desktop overview](https://drive.catap.io/s/24c13732f9478655a99ae9cd3eac7dcbdf7ece27d9edd394?file=142a5aba5c13c26376d397a83e65d1262960f76095bce329).
- `t3-default-dark-1280.png` — [tenant settings](https://drive.catap.io/s/24c13732f9478655a99ae9cd3eac7dcbdf7ece27d9edd394?file=865a317437574c732438a05e38189e0c7efc3392d82717e3).
- `u3-default-dark-1280.png` — [user settings](https://drive.catap.io/s/24c13732f9478655a99ae9cd3eac7dcbdf7ece27d9edd394?file=e02d1222081a9a221e54f747ffdaa07fb01857807dff5f6c).
- `t3-default-dark-390.png` — [mobile tenant settings](https://drive.catap.io/s/24c13732f9478655a99ae9cd3eac7dcbdf7ece27d9edd394?file=a0f76b169ab118132d9024717b5fa66f795261c039929429).

Manual review covered account security in both themes at desktop/mobile widths,
overview and directory details in dark mode at desktop/mobile widths, and the
tenant table on a light desktop. Browser assertions
cover navigation, keyboard focus, no horizontal page overflow, contained table
scrolling, appearance persistence, blocked storage, no-JavaScript operation and
standalone consumption. Screenshots disable transitions to capture settled themes.

Formatting, strict Clippy, all-target ordinary tests (with the pinned Helm binary)
and the documentation build passed. PostgreSQL 18 and native capacity measurements
were not rerun for this visual refinement; no server policy or schema changed.

Build evidence in the same Drive directory:

- `ordinary.txt` — [ordinary tests](https://drive.catap.io/s/24c13732f9478655a99ae9cd3eac7dcbdf7ece27d9edd394?file=6327e4aed12d914aa0205e8bf93b3478791259b60abd21e0).
- `doc.txt` — [documentation build](https://drive.catap.io/s/24c13732f9478655a99ae9cd3eac7dcbdf7ece27d9edd394?file=3fc19904e3b359622c6ba3fdc374973ca15c3ea968749276).

PostgreSQL 17 validation exercised 128 named proofs. The full run passed 124,
including all twelve browser proofs; four directory assertions still expected
pre-UI-kit CSS class strings. They now assert the rendered lifecycle label, while
browser tests continue to check badges and states. The focused directory rerun
passed all 39 HTTP/storage proofs, including those four, yielding passing evidence
for all 128 proofs across the two runs.

- `postgres-17-first-run.txt` — [full run, including original assertion failures](https://drive.catap.io/s/24c13732f9478655a99ae9cd3eac7dcbdf7ece27d9edd394?file=11058e4c6d4b2a7ca66e427570c306768466950245878404).
- `postgres-17-directory-rerun.txt` — [39 passing directory proofs](https://drive.catap.io/s/24c13732f9478655a99ae9cd3eac7dcbdf7ece27d9edd394?file=a0e66b15ec7d8a71414963955aae2a6d4e558fbcaa6146fd).
- `clippy.txt` — [strict Clippy](https://drive.catap.io/s/24c13732f9478655a99ae9cd3eac7dcbdf7ece27d9edd394?file=1cea2d60503b26d33fa87a00969af5f455ff00c9eaf66da9).

### Border refinement verification

The later button reference adds subtle relief to primary and secondary buttons
through the shared UI stylesheet: a thin outline, top highlight and short shadow.
This visual adjustment preserves dimensions, focus outlines and application
behavior. Formatting, strict Clippy, ordinary all-target tests and documentation
build passed; `directory_screen_t3` passed on PostgreSQL 17. Manual review covered
resting primary/secondary buttons in both themes at 1280px and 390px. No new
behavior tests were added for this cosmetic change; the full storage suite was
not rerun. Captures are in `projects/bloc/.design/button-relief-2026-10-23/`:

- `t3-default-dark-1280.png` — [capture](https://drive.catap.io/s/24c13732f9478655a99ae9cd3eac7dcbdf7ece27d9edd394?file=bef801444fadc9d4459ce107121b472ebe25c075d53e109d).
- `t3-default-1280.png` — [capture](https://drive.catap.io/s/24c13732f9478655a99ae9cd3eac7dcbdf7ece27d9edd394?file=61dbd0e2f55f3d1f0a23ddf1002d1da03d2b5a630ca0c374).
- `t3-default-dark-390.png` — [capture](https://drive.catap.io/s/24c13732f9478655a99ae9cd3eac7dcbdf7ece27d9edd394?file=a00e1627bd7eb394346b6dfde3e01d0776d735b868f723ca).
- `t3-default-390.png` — [capture](https://drive.catap.io/s/24c13732f9478655a99ae9cd3eac7dcbdf7ece27d9edd394?file=ce230ccb25e9cc00f4ab734084e58b35add5e5fde3752414).


For the subsequent border refinement, formatting, strict Clippy, ordinary
all-target tests and the documentation build passed. The existing
`directory_screen_t3` browser proof passed on PostgreSQL 17. Manual review of
tenant settings at 1280px and 390px in both themes confirmed quieter panel/field
borders and active navigation without the dot or outline. The full storage suite
and PostgreSQL 18 were not rerun for this CSS-only change.

Captures are retained in `projects/bloc/.design/subtle-borders-2026-10-23/`:

- `t3-default-dark-1280.png` — [dark desktop](https://drive.catap.io/s/24c13732f9478655a99ae9cd3eac7dcbdf7ece27d9edd394?file=b3e2d994bdb9b2356e92ca1772b03378d513fc319412e66f).
- `t3-default-1280.png` — [light desktop](https://drive.catap.io/s/24c13732f9478655a99ae9cd3eac7dcbdf7ece27d9edd394?file=c0ffcd9fc94bffbb986f5154a45b544a7a7941f51d1d323b).
- `t3-default-dark-390.png` — [dark mobile](https://drive.catap.io/s/24c13732f9478655a99ae9cd3eac7dcbdf7ece27d9edd394?file=b98969880822800fae9bf2c9f764b61452b9b9f68fc7ba2d).
- `t3-default-390.png` — [light mobile](https://drive.catap.io/s/24c13732f9478655a99ae9cd3eac7dcbdf7ece27d9edd394?file=8cab4ece431ab3c7afb08cc0795b132df5a772d1953e203f).

### Rounded control refinement verification

The latest supplied references replace the initial control proportions and tone.
Manual review covered account settings in light/dark at 1280px and 375px,
including the focused field beside resting fields. The shared stylesheet now
provides the compact rounded controls and neutral translucent ring. The existing
`keyboard_order`, `keyboard`, `control_density` and standalone consumer assertions
were adapted for the new focus treatment and dimensions; no application behavior
or authentication policy changed. Forced-colours fallback is implemented but was
not manually exercised in this run.

Formatting, strict Clippy, ordinary all-target tests and the documentation build
passed. PostgreSQL 17 passed all 128 named proofs, including all twelve browser
proofs. The initial run stopped at `deployment_assembly` because Helm was absent
from the process path; the rerun explicitly supplied the installed pinned binary
and passed. PostgreSQL 18 and native capacity were not rerun.

Captures are retained in `projects/bloc/.design/rounded-controls-2026-10-23/`:

- `admin-password-dark-1280.png` — [capture](https://drive.catap.io/s/24c13732f9478655a99ae9cd3eac7dcbdf7ece27d9edd394?file=e55aee4b081877018f74a63f4649ee95db52d6648d0cedbc).
- `admin-password-focus-dark-1280.png` — [capture](https://drive.catap.io/s/24c13732f9478655a99ae9cd3eac7dcbdf7ece27d9edd394?file=beff6db18a7c7568872fb3adee46a0cca3cc01cea327b849).
- `admin-password-1280.png` — [capture](https://drive.catap.io/s/24c13732f9478655a99ae9cd3eac7dcbdf7ece27d9edd394?file=5e2d25e230ddb35d694684d56520c5b61a675ca4b5bec1ba).
- `admin-password-focus-1280.png` — [capture](https://drive.catap.io/s/24c13732f9478655a99ae9cd3eac7dcbdf7ece27d9edd394?file=27aedee9c9f942c3566f30ba83ed7e455ed3df6bc12616a5).
- `admin-password-focus-dark-375.png` — [capture](https://drive.catap.io/s/24c13732f9478655a99ae9cd3eac7dcbdf7ece27d9edd394?file=42b986da1491fe5f3cabea73a4d31a87368858b5037bc2c9).
- `admin-password-focus-375.png` — [capture](https://drive.catap.io/s/24c13732f9478655a99ae9cd3eac7dcbdf7ece27d9edd394?file=09fe99a2d663389b254a6d29a998d62642eee7660dfda1f5).
- `t3-default-dark-1280.png` — [primary and secondary buttons](https://drive.catap.io/s/24c13732f9478655a99ae9cd3eac7dcbdf7ece27d9edd394?file=1832f098950d85a080e8596949d2df81eca8af81695c2d1a).
- `postgres-17.txt` — [128 passing proofs](https://drive.catap.io/s/24c13732f9478655a99ae9cd3eac7dcbdf7ece27d9edd394?file=2835736f23c6156784fd248f3cf39e1f90c4bbe4767d1d84).

### Neutral dark controls

For the following dark-palette correction, formatting, strict Clippy, ordinary
all-target tests and documentation build passed. `directory_screen_t3` passed on
PostgreSQL 17. Manual review covered dark tenant settings at 1280px and 390px
alongside the green badges, and the unchanged light desktop. Comparing the CSS
with dark branches removed confirmed the light theme and all non-colour styles
are identical. The full storage suite and standalone consumer proof were not
rerun for this token-only correction; its expected dark focus colour was updated.

Captures are in `projects/bloc/.design/neutral-dark-controls-2026-10-23/`:

- `t3-default-dark-1280.png` — [capture](https://drive.catap.io/s/24c13732f9478655a99ae9cd3eac7dcbdf7ece27d9edd394?file=f4643333bc9d21782e0d701ebaac0bb0e288fe9885881534).
- `t3-default-dark-390.png` — [capture](https://drive.catap.io/s/24c13732f9478655a99ae9cd3eac7dcbdf7ece27d9edd394?file=cda3e081e008b1c559d26f40136218341e94929ca03967e4).
- `t3-default-1280.png` — [capture](https://drive.catap.io/s/24c13732f9478655a99ae9cd3eac7dcbdf7ece27d9edd394?file=b9a34509cf1ad57792c33c708f2a8c7be12c8352202a1b0d).

### Shared radius verification

Formatting, strict Clippy, ordinary all-target tests, documentation build and
`directory_screen_t3` on PostgreSQL 17 passed. Manual review covered light/dark
desktop settings, dark mobile settings and the confirmation panel. Static review
confirmed all bounded components in the active UI styles use the shared radius;
remaining literal radii are circular indicators or unboxed section overrides.
No new tests were added for this cosmetic change. The full storage suite and
PostgreSQL 18 were not rerun.

Captures are in `projects/bloc/.design/shared-radius-2026-10-23/`:

- `t3-default-dark-1280.png` — [capture](https://drive.catap.io/s/24c13732f9478655a99ae9cd3eac7dcbdf7ece27d9edd394?file=9923fc3102ec8097b40cbc841eae05701cf8e9bf7a9ccb84).
- `t3-default-1280.png` — [capture](https://drive.catap.io/s/24c13732f9478655a99ae9cd3eac7dcbdf7ece27d9edd394?file=f17185dbbc04fd93d3d867aaf76a447af8a50f5d7d5f1b24).
- `t3-default-dark-390.png` — [capture](https://drive.catap.io/s/24c13732f9478655a99ae9cd3eac7dcbdf7ece27d9edd394?file=aba1e356a56668740c222bb84e84196a57a546dc51eb585e).
- `t3-confirmation-dark-1280.png` — [capture](https://drive.catap.io/s/24c13732f9478655a99ae9cd3eac7dcbdf7ece27d9edd394?file=ab3814591738df2f4a2b903f356cdee65737d0315bb00853).

### Sidebar structure refinement (2026-10-23)

Decision source: the requester supplied Resend screenshots and asked to remove
bloc's workspace header, put tenant/account actions at the top of the sidebar,
and appearance, feedback and help icons at the bottom. This supersedes the
full-width header in the earlier composition. Existing installation administrator
authority and tenant directory semantics remain unchanged.

#### interface-06: navigate through the sidebar menus

Given an authenticated administrator on an overview, security or directory page
When they open the workspace menu
Then they can browse tenants, create a tenant, open account security or log out
And the logout uses the existing session-bound CSRF-protected POST
And no horizontal workspace header appears.

Given the administrator opens Appearance from the sidebar footer
When they choose System, Light or Dark
Then the choice takes effect, persists and shows a check on the selected option
And Escape closes the menu and returns focus to its trigger
And clicking outside closes an open menu.

Given a narrow viewport or disabled JavaScript
When the administrator uses workspace navigation
Then workspace/account links and the logout form remain reachable
And narrow screens retain all three footer controls
And without JavaScript the appearance picker stays hidden and system theme applies.

Coverage: `dashboard_navigation_and_actions` (failed on the old header before
implementation), `interface_theme_picker_is_only_available_inside_the_application`,
and `workspace_menus` exercised by administrator `browser_preview` and directory
arrangement proofs. `browser_session_expiry` now logs out through the directory
sidebar; `browser_no_javascript` exercises the same menu without JavaScript.

Visual review: light/dark tenant settings at 1280px and light mobile at 390px.
Captures in `projects/bloc/.design/sidebar-structure-2026-10-23/`:

- `t3-default-dark-1280.png` — [dark desktop](https://drive.catap.io/s/24c13732f9478655a99ae9cd3eac7dcbdf7ece27d9edd394?file=7ada5ef1dea8ed2f0fda4defadd9a69f9bff295b2906ecb5).
- `t3-default-1280.png` — [light desktop](https://drive.catap.io/s/24c13732f9478655a99ae9cd3eac7dcbdf7ece27d9edd394?file=1692dbbcb4c3dbf1baab40963391604888b42a9870ea28e7).
- `t3-default-390.png` — [mobile](https://drive.catap.io/s/24c13732f9478655a99ae9cd3eac7dcbdf7ece27d9edd394?file=6e0836a68c1a433642700258f25c339477a0826f1dec58b2).

- `appearance-menu-1280.png` — [appearance choices](https://drive.catap.io/s/24c13732f9478655a99ae9cd3eac7dcbdf7ece27d9edd394?file=203dca9677479ffd6eafaa1f31c85d55738d0eb193888b2a).
- `admin-admin-dark-1280.png` — [overview](https://drive.catap.io/s/24c13732f9478655a99ae9cd3eac7dcbdf7ece27d9edd394?file=64386e5196aa60e9325a4cbd287922bc259d6dbff1e568be).

Verification: formatting, strict Clippy, ordinary all-target tests and documentation
build passed. On PostgreSQL 17, all 59 administrator proofs passed across the final
administrator run (58) and focused `browser_preview` rerun (1). The original
browser assertions needed scoping because the account identifier and logout form
now also appear in the sidebar. The throttled-form regression exposed an empty
logout form on unavailable pages; it is now omitted without a CSRF token. The
preview test now clicks an uncovered workspace point when testing outside-click
closure, since the mobile menu can overlap the page heading.
PostgreSQL 18 and native capacity were not rerun; no storage schema, session policy
or authentication protocol changed.

All 46 directory proofs passed on PostgreSQL 17, including the seven real-browser
proofs. Scenario interface-06 is verified by the scoped runs described above.
The final logout alignment adjustment only changes flex alignment inside the menu.

Additional evidence in `projects/bloc/.design/sidebar-structure-2026-10-23/`:

- `workspace-menu-1280.png` — [workspace and account menu](https://drive.catap.io/s/24c13732f9478655a99ae9cd3eac7dcbdf7ece27d9edd394?file=80e65766094a06e562d2a849c9c3c8635d4898add880198b).
- `postgres-17-administrator.txt` — [administrator run, including the preview failure](https://drive.catap.io/s/24c13732f9478655a99ae9cd3eac7dcbdf7ece27d9edd394?file=06e6b39a06088a9d999100b7618924c7357d571bb71a37d1).
- `postgres-17-preview.txt` — [passing focused preview rerun](https://drive.catap.io/s/24c13732f9478655a99ae9cd3eac7dcbdf7ece27d9edd394?file=8a92b6512274f0be92fb50788b7562a64db2c47c540c6b68).
- `postgres-17-directory.txt` — [46 passing directory proofs](https://drive.catap.io/s/24c13732f9478655a99ae9cd3eac7dcbdf7ece27d9edd394?file=afdb9ea79c653f46015c45fd4e4adf36d42db12d19a0b2ef).

The following icon refinement rounds the sidebar SVG geometry (workspace, folders,
logout, overview, display and feedback) while preserving stroke weight, sizing,
labels and interaction. This is cosmetic and adds no behavior scenarios.
The same rounded folder is reused on overview, directory empty states and access
introduction. Library tests, formatting and diff checks passed; browser suites
were not rerun for this SVG-only refinement.

## Frontend consistency refinement — 2026-10-24

Decision source: requester screenshots and instruction to correct all reported
frontend inconsistencies. Supersedes public access appearance selection and
creation shortcuts in the overview/workspace menu above. Authentication behavior
and form submission contracts are unchanged.

### interface-07: focused public access and consistent workspace

Given login, setup or recovery is displayed
When a saved Light or Dark preference exists for the workspace
Then public access follows the system without showing a theme selector
And access controls are at least 48px tall with 16px text
And the introduction contains only the short headline.

Given an administrator opens the workspace
When they navigate among Overview, Tenants and Account security
Then all pages use the same outer content width and gutters
And tables stay within those gutters
And sidebar items have visible spacing and the workspace dropdown fits its menu
And tenant creation is offered on the Tenants list, once per list state.

Given a form has visible fields
When the final field is followed by a notice or actions
Then a divider and spacing separate that field from the footer.

Coverage: public/system theme isolation and removal of dashboard creation shortcuts
are covered by `interface_theme_picker_is_only_available_inside_the_application`
and `dashboard_navigation_and_actions`. Layout requires browser geometry checks;
these do not establish authentication or HTMX interaction acceptance.

Validation for this refinement: rendering-based browser checks passed for login,
recovery, account security and overview at 390, 768 and 1280px in both system
colour schemes (24 combinations). Checked horizontal overflow, access control
height, absent public selector, dropdown bounds and absent overview creation links.
`tenant_creation_has_one_entry_per_list_state` covers empty and populated tenant
lists. Directory table alignment and footer spacing were reviewed in the shared
styles; live database-backed directory/browser interaction suites were not rerun.

### Follow-up: placeholders and public form separators

Requester refinement: every editable text field includes a short placeholder;
visible labels remain. Login and recovery omit field dividers while internal
settings retain them. This supersedes the separator rule in interface-07 for
those two public forms only. Password placeholders contain instructions, never
sample credentials. Hidden protocol fields and appearance choices are excluded.
Validation: compile/render checks cover the shared administrator and directory
form templates; unchanged submission and authentication contracts.

### Follow-up: page heading separation and account width

Requester refinement: remove the divider between page headings and content on
all screens. Account security returns to its narrower 960px container with
48px/40px desktop padding; directory/overview widths remain unchanged. This
supersedes the shared width rule for account security in interface-07. Spacing
continues to separate headings and content; internal form dividers remain.

### Follow-up: tenant creation and administration navigation

Requester decision: the workspace dropdown offers Create tenant directly, without
routing through the full list. Move the list navigation from Workspace to Settings
as Manage tenants; preserve the existing directory administration routes and
contextual list actions. This supersedes interface-07's dropdown creation exclusion.

Given the administrator opens the workspace dropdown
When they select Create tenant
Then they reach `/admin/tenants/new` directly.

Given the administrator uses the sidebar
When they look for directory administration
Then Manage tenants appears under Settings, with the existing active state
And Workspace contains Overview without a Tenants list item.

Coverage: `dashboard_navigation_and_actions` verifies the direct dropdown action,
absence of the list link in the dropdown, and Settings placement;
`tenant_creation_has_one_entry_per_list_state` verifies one contextual list action
in addition to the persistent dropdown action for both list states.
