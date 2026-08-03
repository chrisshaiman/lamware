# Lamware Post-Deploy Smoke Gate

Deterministic Playwright smoke tests that log into the live Keycloak-gated React SPA
and assert the 8 core nav pages render. Run automatically after deploy via `make smoke`
(see the repo `Makefile`); can also be run standalone.

## One-time setup (control node / WSL)

```bash
make smoke-setup        # venv + deps + Chromium, then PROVES a browser can launch
```

`smoke-setup` finishes by actually launching a browser. Downloading one is not the same
as being able to run one: `playwright install` exits 0 even when the host lacks the
browser's shared libraries, so the target used to report success in a state where the
gate could never run (#269).

**Host packages.** Chromium needs system libraries that a headless Debian/Ubuntu/WSL box
usually does not have:

```bash
sudo apt-get install -y libnss3 libnspr4 libasound2t64
# or let playwright pick them:
sudo tests/smoke/.venv/bin/playwright install-deps
```

Or manually:
```bash
cd tests/smoke
python3.12 -m venv .venv
./.venv/bin/pip install -r requirements.txt
./.venv/bin/playwright install chromium
./.venv/bin/python verify_browser.py     # do not skip — this is the step that proves it
```

## Diagnosing a red gate

`make smoke` now checks the control node before it tests the site, so the two causes are
distinguishable rather than both being red:

| Message | Meaning |
|---|---|
| `Chromium cannot launch — CONTROL NODE problem` | your workstation, not the deploy |
| test failures against the live site | the deploy |

## Run

```bash
SMOKE_TEST_PASSWORD='<viewer-test-pw>' ./.venv/bin/python -m pytest -q
```

## Environment variables

| Var | Default | Meaning |
|---|---|---|
| `SMOKE_BASE_URL` | `https://lamware.shaiman.net` | Live site to test. |
| `SMOKE_TEST_USER` | `smoke-test` | Keycloak viewer username. |
| `SMOKE_TEST_PASSWORD` | *(required)* | Viewer password (from ansible-vault). |

## Maintaining selectors

Each route asserts a heading (by accessible role) and one key widget. Widget anchors are
either accessible (search input / drop-zone text) or a `data-testid` on the page root
(`iocs-content`, `techniques-content`, `stats-content`, `pipeline-content`,
`alerts-content`, `evasions-content`). If a page is restructured, update both the React
`data-testid` and the `ROUTES` table in `test_nav_smoke.py`.
