# Contributing to lamware

Thanks for your interest. lamware is a solo-maintained project, but PRs and
issues are welcome — this document tells you what to expect and how to get a
change accepted.

## Before you start

- For anything larger than a small fix, **open an issue first** to discuss
  the approach. It avoids wasted work on both sides.
- Read `docs/SECURITY_CONSTRAINTS.md`. Its rules (detonation-VLAN isolation,
  container flags, secrets handling) are non-negotiable; PRs that relax them
  will not be merged regardless of the feature they enable.
- The full platform runs on dedicated bare metal (see `DEPLOYMENT.md`), so
  most contributors cannot run it end-to-end. That's fine: the Python
  packages (`shared/`, `pipeline/`, `api/`) and the frontend are all
  locally testable, and unit tests are the acceptance bar for most changes.

## Development setup

Python 3.12+:

```bash
pip install -r requirements-dev.txt
pip install -e ./shared -e ./pipeline
pytest shared/tests pipeline/tests
ruff check src/ api/ shared/ pipeline/
```

The API package's deps live in `api/pyproject.toml` but its layout breaks
`pip install -e .` auto-discovery — install its deps the way CI does (see the
"Install api dependencies" step in `.github/workflows/ci.yml`), then run
`pytest api/tests`.

If you change installed package code and tests behave stale, force a
reinstall — this bites everyone once:

```bash
pip install --force-reinstall --no-deps ./shared ./pipeline
```

Frontend (`frontend/`): React 19 + Vite + TypeScript.

```bash
cd frontend && npm ci && npm run build
```

## Pull requests

- Feature branches, one topic per PR. Direct pushes to `main` are reserved
  for docs and config tweaks.
- CI must be green: ruff, pytest (shared/pipeline/api), ansible-lint,
  Terraform validate, and the security scanning job.
- Match the existing style: type hints, docstrings, structured logging.
  Comments explain *why*, not *what*.
- Any code that calls the Claude/Anthropic API must capture and propagate
  token usage (see the "LLM API cost tracking" section in `CLAUDE.md`).
- Tests are expected with behavior changes. Pure functions are the norm in
  the pipeline — if your change is hard to test, that is usually a sign the
  I/O and logic want separating.
- Never commit secrets. Ansible Vault handles deployment secrets; gitleaks
  runs in CI and pre-commit.

## Security issues

Do not open public issues or PRs for suspected vulnerabilities — see
[SECURITY.md](SECURITY.md).

## License

lamware is Apache 2.0. By contributing you agree your contributions are
licensed under the same terms. Add yourself to `AUTHORS` in your first PR if
you'd like credit.
