---
version: alpha
name: bloc-interface-design
description: A minimal, precise interface built around black, white, neutral grays, clear typography, and restrained lime-green highlights. Use compact application chrome, one navigation menu, integrated data surfaces, and consistent components.

colors:
  canvas: "#ffffff"
  canvas-soft: "#fafafa"
  surface-card: "#ffffff"
  surface-muted: "#f4f4f5"
  ink: "#09090b"
  body: "#3f3f46"
  muted: "#71717a"
  hairline: "#ebebee"
  hairline-strong: "#c5ced1"
  primary: "#242b2e"
  primary-hover: "#343f44"
  primary-active: "#3f3f46"
  on-primary: "#fafafa"
  accent: "#a3e635"
  accent-hover: "#bef264"
  accent-active: "#84cc16"
  accent-soft: "#ecfccb"
  accent-ink: "#365314"
  on-accent: "#09090b"
  focus: "#586f7a"
  semantic-error: "#b91c1c"
  semantic-error-soft: "#fef2f2"

typography:
  sans: "system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif"
  mono: "ui-monospace, SFMono-Regular, Menlo, Consolas, monospace"

rounded:
  component: 12px
  circle: 50%

spacing:
  xxs: 4px
  xs: 8px
  sm: 12px
  base: 16px
  md: 20px
  lg: 24px
  xl: 32px
  xxl: 48px
  section: 80px
---

# bloc interface design

The requester refined the visual direction on 2026-10-23: preserve the existing
colours and use Supabase as the primary reference, followed by Cursor and Slack.
Their supplied Supabase settings screenshot supersedes the earlier rail-based
composition: use one navigation menu, no separate black strip and no “b” icon.
The later Resend screenshots remove the workspace header and move the workspace
menu and utility controls into the sidebar, retaining the approved colours.

## Visual direction

Use one quiet full-height navigation sidebar without a workspace header. Navigation and
content share the theme's canvas, separated by thin rules. Avoid an inset,
rounded application frame. Center settings in a restrained content column, with
bordered groups, aligned field rows and a separate action footer. Keep controls
compact and emphasize active navigation and focused inputs without heavy fills.

The follow-up refinement softens separators and resting field borders in both
themes. Keep rules at 1px; use quieter neutral colours rather than changing the
layout. Active navigation uses a neutral fill and medium-weight text, without a
border or green dot. The subsequent supplied control references introduce a
cool charcoal surface, more visible control edges and 12px control corners.
Fields use a translucent ring in the same neutral hue as their focused border;
error colours remain distinct.
The requester approved the light controls but rejected the blue cast in dark
mode. Dark controls therefore use the workspace's neutral graphite/zinc family,
including borders and focus, so the existing lime status badges remain the
colour accent. Light-mode values and control geometry stay unchanged.

The references were inspected through their actual product imagery:

- [Slack's sidebar update](https://slack.com/whats-new): historical reference for
  grouped navigation; its contrasting rail is not part of the current direction.
- [Supabase Studio on its product page](https://supabase.com/): compact navigation,
  thin separators and integrated data tables. Its
  [navigation guidance](https://supabase.com/changelog/33670-upcoming-breaking-change-to-dashboard-navigation)
  reinforces keeping context and account actions distinct.
- [Cursor's agent interface](https://cursor.com/changelog/2-0): restrained chrome,
  quiet type hierarchy and content-centered work areas.

These are design references. Do not copy their branding, add their unrelated
features, or populate bloc with invented metrics, search fields or inactive links.

## Colour and appearance

Keep the frontmatter palette. Most surfaces are neutral; lime marks deliberate
emphasis and labeled positive states. Primary controls use charcoal with light
text in both themes. White text on bright lime and lime body text on
white are prohibited. Error red remains semantic.

Both themes are complete and use the same components. Initial appearance follows
the system. A footer icon opens System, Light and Dark choices in the workspace; public access screens always follow the system without a selector. The manual
choice persists in browser-local storage and synchronizes across tabs; failure
to access storage does not prevent rendering or the current selection. Without
JavaScript, system appearance works and the unavailable selector remains hidden.

| Role | Light | Dark |
| --- | --- | --- |
| Workspace | `#ffffff` | `#18181b` |
| Outer chrome | `#f4f4f5` | `#09090b` |
| Muted surfaces | `#f4f4f5` | `#27272a` |
| Main text | `#09090b` | `#fafafa` |
| Secondary text | `#71717a` | `#a1a1aa` |
| Separators | `#ebebee` | `#2e2e33` |
| Control surfaces | `#f3f5f5` | `#252528` |
| Resting field borders | `#c5ced1` | `#48484f` |
| Hover/focused field borders | `#8b9ba2` | `#71717a` |
| Field focus ring | focused border at 24% opacity | focused border at 24% opacity |
| Primary control fill | `#242b2e` | `#343438` |
| Primary control border | `#46565e` | `#64646c` |
| Link/button focus outline | `#586f7a` | `#a1a1aa` |
| Positive fill/text | `#ecfccb` / `#365314` | `#365314` / `#ecfccb` |
| Error fill/text | `#fef2f2` / `#b91c1c` | `#b91c1c` / `#fef2f2` |

The public access introduction uses near-black in either theme. The authenticated
shell uses the theme canvas throughout, including the single sidebar.

## Typography and components

Icons use a consistent outline weight with round caps and joins, rounded
rectangle corners and curved transitions in folders, workspace and utility symbols.
Preserve their existing size and avoid mixing sharp and rounded versions of the
same symbol.

Use system sans-serif and monospace for technical identifiers; no font download
is needed. Page headings are 22px/600; access headings are 28px/600, reduced to
22px below 640px. Section headings are generally 13–15px/600 (empty-state
headings use 16px), body and fields 13–14px, desktop buttons 12px, and metadata
11–12px. Fields use 16px text below 640px. Use sentence case and
restrained tracking. Long names, identifiers and error text must wrap safely.

Buttons, inputs and selects have 12px corners. Desktop buttons are at least 30px
high with 12px text; inputs are at least 32px high with 13px text. Below 640px
and for coarse pointers, the shared button/input minimum-height tokens are 44px.
This does not apply to every link: directory record links retain a 28px minimum.
Public access inputs and buttons use 48px minimum heights and 16px text. Neutral
secondary buttons use thin borders. Following the requester's button reference,
filled buttons have a subtle 1px outline, an inset top highlight and a short
outer shadow in both themes. Pressing replaces the raised shadow with an inset
shadow; ghost and disabled buttons stay flat. Keep one primary action per group. Inputs
have visible labels, persistent guidance and adjacent error messages. Field focus
uses a 3px neutral ring at 24% opacity with no additional outline or fill change;
invalid input and textarea fields keep their semantic red border and use a
16% error-colour ring. No custom
input is required where a native control fits.

Tables span the workspace content width with subtle row dividers, muted headers
and restrained hover fills. Do not enclose every data cell or section in a card.
Lists retain semantic tables and a keyboard-accessible horizontal scroll region.
Empty states supply a useful action and explain the real absence.

All bounded components share the 12px `--ui-radius`: controls, navigation items,
badges, notices, panels, entry tiles, icon containers and standalone table
wrappers. The control-radius token inherits it. Circular avatars and status dots
remain circular; unboxed layout sections and edge-to-edge tables keep straight
separators. Badges retain text and a small dot for a positive state. Colour
alone never conveys lifecycle state. Panels use the shared radius where an actual
bounded surface is useful. Directory detail forms use vertically stacked,
bordered profile, lifecycle and record sections in a single column. Record
metadata uses a two-column label/value grid within its section. Feedback uses the same notice and field-error components in
both full pages and fragments.

## Workspace composition

Desktop: one full-height 240px sidebar, with a workspace/account menu at the top
and appearance, feedback and help icons at the bottom. No horizontal workspace header. The sidebar
narrows to 192px at 900px. Below 640px a compact header keeps the hamburger beside the bloc workspace
dropdown. Following the supplied ChatGPT mobile reference, the button reveals navigation
on the left while the header and page slide right, leaving a 68px page strip
with rounded top and bottom corners and one continuous shadow. Retain desktop navigation groups,
roomier mobile rows and bottom utility controls. Tapping the page strip or pressing Escape dismisses navigation. Keyboard focus stays inside the open drawer, background
content is inert, and reduced-motion preferences disable animation. Desktop navigation remains visible.
Without JavaScript, the labeled navigation stays expanded and usable.
Use the plain `bloc` name with an installation descriptor in the workspace menu.
Tenant navigation opens the existing directory; it does not change administrator
authority or introduce tenant-bound sessions. Feedback opens the project issue
form and help opens its README. Icon controls have hover/focus labels. Menus close
on Escape and outside clicks with JavaScript; native disclosure works without it. Navigation and
appearance stay outside the HTMX replacement target. Breadcrumbs appear only in
the page content.

The overview has a directory entry, administrator account actions and compact
installation details. It does not invent totals, charts or activity. Settings use
a centered column up to 960px including gutters. Profile fields are organized in
bordered rows: label/help on the left and input on the right at desktop widths,
stacked below 1000px. Lifecycle controls and immutable metadata follow the profile.
Creation forms remain at most 680px wide. Use 32–40px desktop content gutters,
24px at intermediate sizes and 16px on mobile. Table overflow stays contained.

## Access screens

Public sign-in, setup and recovery use a split composition: a near-black brand
introduction on the left and a focused unboxed form on the right. The introduction
names only implemented capabilities. Below 900px it is omitted, leaving the form
and simple header. Account/password changes stay inside the authenticated shell.
Error, closed-setup, unavailable and expired states keep the established messages
and recovery behavior; a new arrangement does not change authentication policy.

## Portable UI boundary

[UI assets](docs/ui-system.md) define opt-in component styles, tokens and generic
appearance behavior. Application layout and domain behavior stay separate.
Components must work in ordinary HTML without Rust, Askama or HTMX. Keep current
assets locally served; extraction and CDN publication are future work.

## Accessibility and verification

Keep semantic headings, native controls, visible labels, a skip link and visible
keyboard focus. Links and buttons retain 2px focus outlines; fields use the
neutral ring described above, with a system-colour outline in forced-colours
mode. Target 4.5:1 normal text contrast. Field borders and translucent rings are
deliberately softer; do not claim they meet 3:1 non-text contrast. Keep persistent labels and visible
field surfaces. Shared buttons and fields use a 44px minimum on narrow viewports
and coarse pointers; directory record links retain a 28px minimum. Workspace
utility icons are 44px in those modes. The workspace-menu summary is at least
52px on desktop and 44px below 640px.

Directory fields associate guidance and errors through `aria-describedby`.
Administrator access/password forms associate field errors, but the visible
password guidance is currently not associated with its input. This is a known
accessibility limitation of the current templates.
Respect reduced-motion preferences. No essential action may depend on hover.

Check desktop and narrow widths, both themes, long content, keyboard navigation,
no-JavaScript forms, repeated HTMX swaps, loading/error feedback and history.
The [portable interface behavior record](docs/behaviors/portable-interface.md)
records current verification and any limits. Visual evidence lives in Drive.

## Frontend consistency refinement

Public access keeps only the short brand headline beside the form. Internal forms
retain a divider after the last field and breathing room before notices/actions.
Login and recovery use stacked fields without dividers. All editable text fields
include concise placeholders alongside their persistent visible labels.
Overview and directories share a 1200px content container and
40px/32px desktop padding; account security uses a narrower 960px container
with 48px/40px desktop padding. Page headers have no bottom divider; tables stay within those gutters. Sidebar links have
6px vertical separation and workspace dropdowns fit the sidebar width. The workspace dropdown offers Create tenant directly. Manage tenants lives
under Settings in the sidebar; the list retains its contextual creation action.
