# Generating screenshots & the demo GIF

The README's visuals are generated reproducibly from the real tool — no
hand-edited mockups. Regenerate them any time the UI changes.

## Terminal GIF (CLI demo)

Uses [vhs](https://github.com/charmbracelet/vhs) (Charm) — a terminal recorder
driven by a script, so the GIF is deterministic and re-runnable.

```bash
go install github.com/charmbracelet/vhs@latest
go build -o exalm ./cmd/exalm && export PATH="$PWD:$PATH"
vhs docs/assets/demo.tape          # → docs/assets/demo.gif
```

The tape lives at [`docs/assets/demo.tape`](assets/demo.tape); edit it to change
what the demo shows.

## Dashboard screenshots (PNG)

Uses [shot-scraper](https://shot-scraper.datasette.io/) (Playwright under the
hood) to screenshot the live dashboard headlessly.

```bash
pipx install shot-scraper && shot-scraper install

export EXALM_LLM_PROVIDER=mock
exalm syslog analyze --file examples/syslog/wsl-live-session.jsonl --output web &
sleep 2

# Full dashboard (findings panel + charts)
shot-scraper http://localhost:7433 -o docs/assets/dashboard.png \
  --width 1360 --height 900 --wait 1500 --retina

# Dark + light both look right — capture light too if you want:
# shot-scraper http://localhost:7433 -o docs/assets/dashboard-light.png --width 1360 --wait 1500 --javascript "document.documentElement.setAttribute('data-theme','light')"
```

Recommended shots for the README:
1. **`dashboard.png`** — the findings panel + signal stats (the hero view).
2. **`investigation.png`** — the AI Analysis page (chat + evidence tree). Navigate
   to it first: `--javascript "location.hash='' ; document.querySelector('[data-page=ai]')?.click()"`.
3. **`remediation.png`** — a finding's remediation dialog (click a finding card).

## Alternatives

- **[asciinema](https://asciinema.org/)** + [svg-term](https://github.com/marionebl/svg-term-cli)
  for a lightweight, copy-pasteable terminal cast instead of a GIF.
- **[silicon](https://github.com/Aloxaf/silicon)** for a static "code card" image
  of a single command's output.
