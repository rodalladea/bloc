---
version: alpha
name: bloc-interface-design
description: A minimal, precise interface built around black, white, neutral grays, clear typography, and restrained lime-green highlights. Use generous whitespace, thin borders, and consistent components to make content and actions easy to scan.

colors:
  canvas: "#ffffff"
  canvas-soft: "#fafafa"
  surface-card: "#ffffff"
  surface-muted: "#f4f4f5"
  ink: "#09090b"
  body: "#3f3f46"
  muted: "#71717a"
  hairline: "#e4e4e7"
  hairline-strong: "#a1a1aa"
  primary: "#18181b"
  primary-hover: "#27272a"
  primary-active: "#3f3f46"
  on-primary: "#fafafa"
  accent: "#a3e635"
  accent-hover: "#bef264"
  accent-active: "#84cc16"
  accent-soft: "#ecfccb"
  accent-ink: "#365314"
  on-accent: "#09090b"
  focus: "#4d7c0f"
  semantic-error: "#b91c1c"
  semantic-error-soft: "#fef2f2"

typography:
  sans: "system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif"
  mono: "ui-monospace, SFMono-Regular, Menlo, Consolas, monospace"

rounded:
  sm: 2px
  md: 3px
  lg: 4px
  xl: 4px

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

This file is the visual reference for agents designing or changing bloc's
interface. It describes the intended direction, not a claim that every component
or feature already exists. Apply it to server-rendered HTML and existing styles;
keep changes within the repository's implementation guidance.

## Visual direction

Make the interface clean, structured, and primarily black and white. Neutral gray
surfaces and thin borders establish hierarchy. Strong headings, compact controls,
and generous space around content give the interface a quiet, practical character.
Lime green provides an occasional point of emphasis.

- Use white as the default page canvas, near-black for headings and primary actions,
  and neutral grays for secondary text, dividers, and subdued surfaces.
- Keep most of every screen monochrome. Lime is a highlight, not a page background
  or the default color for every interactive element.
- Use clear component boundaries, consistent alignment, and very subtle corner radii.
- Let typography and spacing carry hierarchy. Avoid decorative gradients, glows,
  textured backgrounds, oversized pills, and ornamental illustrations.
- Design around bloc's content and actual capabilities. Product previews should
  represent bloc screens and clearly identify planned functionality.

## Color and emphasis

Use the frontmatter tokens as the shared palette. Map them to CSS custom properties
when implementing styles instead of scattering literal colors across components.

| Role | Tokens | Treatment |
| --- | --- | --- |
| Page and panels | `canvas`, `canvas-soft`, `surface-card` | White or subtly shaded neutral surfaces |
| Subdued regions | `surface-muted` | Secondary panels, table headers, code backgrounds, hover fills |
| Text | `ink`, `body`, `muted` | Strong headings, readable body copy, secondary metadata |
| Borders | `hairline`, `hairline-strong` | Thin dividers; stronger outlines where controls need definition |
| Default action | `primary`, `on-primary` | Near-black fill with near-white text |
| Highlight | `accent`, `on-accent` | Lime fill with near-black text or icons |
| Subtle highlight | `accent-soft`, `accent-ink` | Pale lime surface with dark green text |
| Keyboard focus | `focus` | Visible outline with separation from the component |
| Error | `semantic-error`, `semantic-error-soft` | Validation and destructive states only |

Use lime for a small active indicator, a selected badge, or an occasional emphasized
action. Default primary buttons and the bloc wordmark remain monochrome. When an
accent button is appropriate, use its matching hover and active tokens.

Never use bright lime for small text on white or white text on lime. Use
`accent-ink` for green text on light surfaces. Pair status colors with text or
icons; a green highlight alone must not imply success. Error red is a semantic
exception, not an additional decorative accent.

The default theme is light. If a dark theme is introduced, preserve the same
hierarchy using near-black canvases, neutral dark panels, light text, and restrained
lime. Define and check a complete dark palette before shipping it.

## Typography

Use the system sans-serif stack for the interface. Use the monospace stack for
code, technical identifiers, and configuration examples. No custom font download
is required.

| Role | Size | Weight | Line height | Tracking |
| --- | --- | --- | --- | --- |
| Landing headline | 48–64px desktop, 32–40px mobile | 700 | 1.1 | -0.04em |
| Page heading | 30–36px | 600–700 | 1.2 | -0.03em |
| Section heading | 22–24px | 600 | 1.3 | -0.02em |
| Card heading | 16–18px | 600 | 1.4 | Normal |
| Body | 16px | 400 | 1.6 | Normal |
| Controls and navigation | 14px | 500 | 1.4 | Normal |
| Secondary copy and metadata | 13–14px | 400 | 1.5 | Normal |
| Code | 13–14px | 400 | 1.6 | Normal |

Use sentence case for labels and headings. Keep body copy to roughly 60–75
characters per line. Prefer concise labels and short supporting descriptions.
Reserve tight tracking for larger headings, and avoid uppercase navigation or
widely tracked labels as the default.

## Layout and spacing

Use a 4px spacing unit with the frontmatter scale. Keep content centered in a
container up to 1200px wide, with 16–24px horizontal gutters on small screens and
24–32px on larger screens.

- Landing sections: 64–80px vertical spacing on desktop, 40–48px on mobile.
- Application sections: 24–32px between related groups.
- Cards: 20–24px padding, with 16–24px gaps between cards.
- Forms: 16–24px between fields and 6–8px between a label and its control.
- Navigation: approximately 64px high with a subtle bottom border.

Align headings, descriptions, controls, and tables to a shared grid. Use two or
three columns only when the content benefits; collapse to a single column when
space becomes constrained. Administrative screens can be denser than landing
pages while retaining clear grouping and comfortable control spacing.

## Components

### Navigation

Place the lowercase bloc wordmark at the left, followed by a small set of relevant
links. Keep secondary actions understated. Use near-black text for the current
page, with an underline or subtle neutral background; a small lime marker is
optional. Keep borders and spacing consistent with the content container.

### Buttons and links

Default primary buttons use `primary` and `on-primary`, with `primary-hover` and
`primary-active` interaction states. Secondary buttons use a white surface, dark
text, and a 1px border. Ghost buttons use transparent backgrounds with a neutral
hover fill. Use 3px corner radii, 14px medium-weight labels, and 12–16px horizontal
padding. Aim for 40–44px control heights, with at least 44px touch targets.

Use accent buttons sparingly where emphasis is intentional. Keep one clear primary
action per action group. Inline links should be distinguishable through underlines
or another persistent non-color cue. Disabled controls should look subdued and
remain distinguishable from enabled controls.

### Cards and panels

Use white surfaces, 1px `hairline` borders, and 4px corner radii. Titles are dark
and semibold; descriptions use secondary text. Prefer flat surfaces for normal
content. A subtle neutral shadow is acceptable for a floating menu, popover, or
dialog when needed to separate overlapping layers.

### Forms

Use visible labels, white inputs, clear neutral borders, and 3px corner radii.
Place supporting text below the field. Show focus visibly and place validation
messages next to the affected control. Do not rely on placeholder text as a label.
Keep inputs comfortably sized and allow long values to fit without breaking layout.

### Tables and lists

Use aligned columns, subtle row dividers, muted headers, and a light neutral hover
fill for interactive rows. Avoid enclosing every cell in a box. Use monospace only
for technical values. Place row actions consistently and keep them keyboard
accessible. Provide clear empty, loading, and error states as functionality lands.

### Badges and status

Default badges use neutral fills, dark text, compact padding, and a subtle 2px
corner radius. Reserve pale lime with dark green text for deliberate emphasis or a
labeled positive state. State meaning in words and use an icon where useful.
Avoid assigning a different decorative color to every category.

### Code and technical content

Use a muted neutral background, a thin border, and the monospace font. Keep
syntax coloring restrained. Allow long code samples to scroll within their own
container without causing the page to overflow.

### Landing content and footer

Use a strong headline, a short description, and a compact action group. Keep any
product illustration aligned with the same borders, colors, and typography as the
interface. The footer uses a top divider, subdued links, and modest spacing.
Include only sections and actions appropriate to implemented or explicitly planned
capabilities.

## Responsive behavior and accessibility

Let layout changes follow content needs. Use 640px and 1024px as initial layout
breakpoints: single-column on small screens, two columns where useful on medium
screens, and the full content grid on larger screens.

- Collapse navigation when links no longer fit and give the menu control a label.
- Stack action groups and form layouts when needed; avoid clipped labels.
- Keep tables readable with contained horizontal scrolling or a suitable list view.
- Preserve visible keyboard focus on every interactive element. Use a 2px `focus`
  outline with a 2px offset on light surfaces; verify it against adjacent colors.
- Check text and control contrast in their actual states. Target at least 4.5:1
  for normal text and 3:1 for large text and essential control boundaries.
- Use semantic headings, labels, links, and buttons. Never rely on color alone.
- Keep transitions short, around 120–180ms, and respect reduced-motion preferences.
  Avoid decorative entrance sequences and animated backgrounds.

## Agent checklist

1. Follow this direction for new UI and changes to existing components.
2. Reuse shared tokens and existing component patterns before adding variants.
3. Keep black, white, and neutral grays dominant; use lime with a clear purpose.
4. Specify hover, active, focus, disabled, and error states where applicable.
5. Review small-screen layout, keyboard access, long content, and contrast.
6. Keep examples synthetic and distinguish planned features from working behavior.
7. Update this reference when a deliberate design decision changes the system.
