# bloc UI system

The reusable surface is `assets/ui.css` plus `assets/ui.js`. They are kept inside
bloc and served locally. They do not depend on Rust, Askama, HTMX, a build system,
a font service or an external runtime. `assets/admin.css` and
`assets/directory.css` contain bloc's application layouts; their scripts retain
request, validation, focus and recovery behavior.

## Plain HTML consumption

Load the stylesheet and script once, with the script in the head so a saved
appearance is applied before the document paints. Either put `class="ui"` on
`html` for a whole application, or wrap the intended UI region with that class.
Content outside an opted-in region is not restyled. The regression fixture at
[ui-consumer.html](../tests/fixtures/ui-consumer.html) is an executable example
using only the shared assets.

```html
<link rel="stylesheet" href="ui.css">
<script src="ui.js"></script>

<section class="ui">
  <label class="ui-theme" data-ui-theme-picker hidden>
    <span>Appearance</span>
    <select aria-label="Appearance" data-ui-theme-control>
      <option value="system">System</option>
      <option value="light">Light</option>
      <option value="dark">Dark</option>
    </select>
  </label>
  <div class="ui-panel">
    <h1>Workspace</h1>
    <label class="ui-field">Name<input name="name"></label>
    <button type="button">Save</button>
    <a class="ui-button ui-button--secondary" href="/">Cancel</a>
  </div>
</section>
```

The consumer supplies content, real navigation and application actions. The UI
runtime makes no requests. There are no required bloc endpoint names. If the
assets move later, the consuming document chooses their URLs.

## Components and states

Within the UI scope, native buttons, inputs, selects, textareas, headings and
links have the base appearance. Compose the following classes with semantic HTML:

| Component | Class / variant | Consumer responsibility |
| --- | --- | --- |
| Link styled as button | `ui-button` | Real destination; link remains a link |
| Secondary / ghost button | `ui-button--secondary`, `ui-button--ghost` | Choose one main action per group |
| Field group | `ui-field` | Visible label and control association |
| Settings row | `ui-field ui-field--row` | Label, input, help and error; stacks below 1000px |
| Busy button | `button[aria-busy="true"]` | Disable during submission; supply an action label and a polite live status; clear busy state on completion |
| Help / error | `ui-help`, `ui-field-error` | Consumer supplies `aria-describedby` and `aria-invalid`; classes only style the text |
| Notice | `ui-notice`, `ui-notice--error` | Appropriate alert/status role and focus policy |
| Panel | `ui-panel` | Heading and meaningful grouping |
| Status | `ui-badge`, `ui-badge--positive` | Text states meaning independently of colour |
| Data table | `ui-table` within `ui-table-scroll` | Table headers, labeled/focusable scroll region |
| Technical values | `ui-mono` | Content with safe wrapping |
| Icon | `ui-icon` | SVG viewBox, accessible label or decorative hiding |
| Appearance | `ui-theme` and data attributes above | One persistent chrome region for the picker |

Desktop controls use `--ui-button-height: 30px`, `--ui-input-height: 32px` and
`--ui-radius: 12px`, shared by all bounded components. `--ui-control-radius`
inherits that token. Panels, notices, badges and standalone table wrappers use
the same rounding as buttons and fields. Circular indicators stay circular;
unboxed layout sections keep straight separators. Coarse pointers and viewports below 640px use 44px
for both minimum-height tokens. Application links can have independent sizing;
directory record links retain a 28px minimum. The access appearance select uses
the button-height token. Light controls use cool neutral tones; dark controls use
graphite/zinc tones matching the workspace and its lime accents. Focused
fields keep their fill and use a 3px ring in the focused border's hue at 24%
opacity. Invalid inputs and textareas retain their error border and use an
error-colour ring at 16% opacity, with an inset outline while resting; selects have no dedicated invalid-state rule. Keyboard focus
on links/buttons retains an outline, and forced-colours mode also outlines fields.

Error notices use a muted tint in both themes, neutral body text, red links and a
subtle, even border. `--ui-error-line` supplies the quieter surrounding border.

Primary and secondary buttons share a thin outline, inset top highlight and
short shadow for subtle relief. The `--ui-button-*` tokens define their theme
colours. Pressed buttons use an inset shadow; ghost and disabled buttons stay
flat. These styles travel with `ui.css` and need no JavaScript.

Native disabled controls, invalid inputs/textareas, focus and hover receive
corresponding styling. Directory forms associate help and error text with their
fields. Administrator access/password forms currently associate errors only;
their visible password guidance is not linked through `aria-describedby`.
Use inline field errors for validation, without a duplicate notice. General errors
use `ui-notice ui-notice--error` as the first element in the main content, above
headings and form fields. Retain recovery actions. bloc focuses the invalid field
after validation and prioritizes a general alert when one is present.

The consumer owns pending state, validation semantics, focus after navigation,
confirmation and the effect of an action. No authentication or mutation policy
belongs in these assets. Do not load the script more than once or inject it with
fragments. Appearance controls belong to persistent chrome; ordinary components
need no initialization after an HTML replacement.

## Theme contract

Appearance is a document-wide choice: `system`, `light` or `dark`, expressed as
`data-ui-theme` on the document element. The runtime stores only that choice in
`bloc-ui.appearance` and synchronizes it through browser storage events. Blocked
storage preserves the current selection without persistence. With no JavaScript,
CSS follows the operating-system appearance and the picker stays hidden.

Components use `--ui-*` semantic custom properties defined by the stylesheet.
Override these on the UI scope for another host's branding. Override foreground
and background pairs together and verify their contrast. The neutral palette,
lime accent and light/dark mappings for bloc are recorded in [DESIGN.md](../DESIGN.md).
The stylesheet uses `light-dark()` and targets browsers that support that CSS
feature; the current browser proof uses Chromium. No legacy-browser fallback is
claimed.

## Extraction boundary

Copying the two shared assets and their consumption documentation is sufficient
for the demonstrated controls and appearance behavior. It does not copy bloc's
workspace pages, forms, routes, sessions or HTMX handlers. Additional interactive
components need their own keyboard/focus/state contract when an actual screen
requires them; the current kit does not claim a complete menu/dialog catalog.

A separately published package, version policy and CDN deployment are deferred.
Do not switch bloc to an external CDN or weaken CSP to demonstrate portability.

Workspace appearance can also use buttons with `data-ui-theme-choice="system"`,
`"light"` or `"dark"` inside a hidden `data-ui-theme-picker`. The runtime reveals
the picker, updates `aria-pressed` and preserves the same storage contract. A
native `details` marked `data-ui-dropdown` closes on Escape (returning focus to
its summary), outside clicks and appearance selection. These disclosures retain
ordinary Tab navigation; they do not claim ARIA menu/arrow-key semantics.

## Button loading

A busy button shows a 16px neutral spinner before its label using only `ui.css`.
Keep the action visible (for example “Signing in…” or “Saving changes…”), set
`aria-busy="true"` and `disabled`, and remove both when the request finishes.
Reduced motion replaces rotation with a static indicator. No progress percentage
is implied. The styles use theme tokens and need no initialization.

bloc's request scripts read `data-pending-label`, restore the original label after
failure, and announce the pending action through a separate `.ui-sr-only` status
region. This replaces the visible message beneath submit buttons. Native forms
remain usable without JavaScript; directory navigation keeps its existing status.
