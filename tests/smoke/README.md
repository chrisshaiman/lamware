# Lamware Post-Deploy Smoke Gate

Deterministic Playwright smoke tests that log into the live Keycloak-gated React SPA
and assert the 8 core nav pages render. Run automatically after deploy via `make smoke`
(see the repo `Makefile`); can also be run standalone.

## One-time setup (control node / WSL)

```bash
make smoke-setup        # creates tests/smoke/.venv, installs deps, installs Chromium
```

Or manually:
```bash
cd tests/smoke
python3.12 -m venv .venv
./.venv/bin/pip install -r requirements.txt
./.venv/bin/playwright install chromium
```

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
