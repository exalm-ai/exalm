# Exalm dashboard — UX/UI review & how to make it more professional

Based on the live dashboard (`exalm <analyzer> analyze --output web`) and the
frontend code (`internal/web/static/*`, `internal/web/templates/*`). Two fixes
from this review already landed (see "Already fixed"); the rest is a prioritized
plan with concrete, low-risk tooling.

## What's already good
- Coherent dark theme, clear information architecture (sidebar: Dashboard ·
  Log Explorer · AI Analysis · Alerts · Settings), severity-coded finding cards,
  signal stat tiles, charts, a conversational investigation workspace, and a
  remediation dialog. The product has real depth and a modern baseline.
- No build step: static assets are `//go:embed`-ed vanilla JS/CSS. Keep this —
  it's a feature (single binary, trivial to hack on). All recommendations below
  respect "no bundler required."

## Already fixed in this pass
- **"Likely cause" duplicated the detail** on every finding card — now shows the
  real root cause (`rootOf` prefers `Finding.RootCause`).
- **Cards blended into the background** (page `#070b14` vs card `#0e1626` were
  nearly identical, so full-width cards looked narrow) — lifted the
  `--panel/--panel2/--border` tokens for clear elevation.

## Top issues & the highest-ROI fixes (priority order)

### 1. Two competing design-token systems  →  consolidate to one
`internal/web/static/style.css` defines one palette (`--surface/--text/--brand/
--sev-*`), while `dashboard.js` **injects a second, differently-named palette at
runtime** (`--panel/--fg/--crit/--accent`, `dashboard.js:23-40`). The JS set
shadows the CSS set. This is the root cause of most inconsistency and makes
theming fragile.
- **Do:** pick one naming scheme, define it once in `style.css` `:root` +
  `[data-theme=light]`, delete the JS injection (or make the JS the only source
  and thin out `style.css`). One token vocabulary.
- **Tool:** [**Open Props**](https://open-props.style/) — a drop-in set of CSS
  custom properties (color, size, shadow, easing scales) with **no build step**.
  Adopt its scales as your token values and the whole UI gains a consistent,
  professionally-tuned rhythm. [**Radix Colors**](https://www.radix-ui.com/colors)
  is an excellent accessible palette to borrow values from.

### 2. Everything is inline `style="…"` strings  →  move to CSS classes
`dashboard.js` builds markup with large inline styles. That blocks reuse,
hover/focus states, and theming, and makes the code hard to change.
- **Do:** extract the repeated patterns (card, chip, stat tile, button, table
  row) into a small BEM/utility class layer in `style.css`. You don't need a
  framework — a ~150-line utility sheet covers it.
- **Optional tool:** a classless/utility base like
  [**Pico.css**](https://picocss.com/) or the utility subset of
  [**Tailwind via CDN/standalone CLI**](https://tailwindcss.com/blog/standalone-cli)
  (the standalone CLI needs no Node/bundler and can emit one embedded `.css`).

### 3. Dashboard fetches fonts from Google  →  self-host (privacy + polish)
`templates/index.html` loads IBM Plex from `fonts.googleapis.com`. For a
**privacy-first** tool that promises "no phone home," the dashboard making an
external call to Google is an off-brand inconsistency (and it breaks in
air-gapped/offline use).
- **Do:** self-host the woff2 files under `static/fonts/` with `@font-face`, or
  use a pure system-font stack. Removes every external request from the UI.
- **Tool:** [`google-webfonts-helper`](https://gwfh.mranftl.com/fonts) to grab
  the exact woff2 subset + `@font-face` CSS.

### 4. Accessibility & contrast pass
Mid-gray text (`--muted #8294aa`) on the dark bg is borderline for small text,
and inline styles rarely include focus rings.
- **Do:** ensure WCAG AA contrast, visible `:focus-visible` rings, `aria-label`s
  on icon-only buttons, and keyboard nav through findings/tabs.
- **Tools:** [**Lighthouse**](https://developer.chrome.com/docs/lighthouse) (in
  Chrome DevTools), [**axe DevTools**](https://www.deque.com/axe/devtools/), or
  headless [**pa11y**](https://pa11y.org/) in CI against `--output web`.

### 5. Consistent icon set
Standardize on one SVG icon library, inlined (no external calls).
- **Tool:** [**Lucide**](https://lucide.dev/) (MIT) or
  [**Phosphor**](https://phosphoricons.com/) — clean, consistent, huge sets.

### 6. Polish empty / loading / error states
Make the "no findings", "loading…", and "AI disabled" states look intentional
(icon + one-line explanation + a next action), not bare text.

## Bigger bets (defer past the OSS launch)
- A component framework (**Svelte**, **Preact**, or **htmx + Alpine.js**) +
  **Tailwind** or **shadcn/ui** patterns would modernize the frontend, but it
  adds a build step — not worth blocking launch. Revisit if the dashboard
  becomes a primary surface.
- A docs site: [**Astro Starlight**](https://starlight.astro.build/) or
  **Docusaurus** for `docs/` when the project grows.

## Visual benchmarks to aim at
Open-source ops UIs with a professional feel worth studying:
[**Coroot**](https://coroot.com/), [**Headlamp**](https://headlamp.dev/),
[**Grafana**](https://grafana.com/), and for the terminal aesthetic
[**k9s**](https://k9scli.io/) / [**lazygit**](https://github.com/jesseduffield/lazygit).

## Suggested order of work
1. Self-host fonts (quick, on-brand, removes external calls).
2. Consolidate to one token system (adopt Open Props / Radix values).
3. Establish an elevation + spacing scale; extract the worst inline styles to classes.
4. Standardize icons (Lucide); polish empty/loading states.
5. Run Lighthouse/axe; fix contrast + focus.
6. Generate README visuals (vhs GIF + shot-scraper PNGs — see docs/screenshots.md).

Items 1–3 alone move the dashboard from "solid" to "polished" and are all
no-build-step, low-risk changes.
