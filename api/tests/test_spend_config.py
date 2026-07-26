# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""Config-source drift guard for the spend router.

spend.py read `LITELLM_URL` / `LITELLM_MASTER_KEY` directly from os.environ while the
deploy template writes `LAMWARE_LITELLM_URL` / `LAMWARE_LITELLM_KEY`. Nothing set the
names it read, so both fell back to defaults and the endpoint returned its zeroed error
payload permanently — silently, because "no spend" and "spend API unreachable" render
the same. It was the only file in api/ bypassing `settings`, which is why it drifted
alone: every other router inherits the LAMWARE_ prefix automatically.
"""
import re
from pathlib import Path

API_ROOT = Path(__file__).resolve().parents[1]
REPO_ROOT = API_ROOT.parent
SPEND = API_ROOT / "app" / "routers" / "spend.py"


def test_spend_router_does_not_read_os_environ():
    """Config must come from settings so the LAMWARE_ prefix is applied consistently."""
    src = SPEND.read_text()
    assert "os.environ" not in src, (
        "spend.py must read config via `settings`, not os.environ — bypassing settings "
        "is what let its env-var names drift from the deploy template.")


def test_spend_router_uses_settings_for_litellm():
    src = SPEND.read_text()
    assert "settings.litellm_url" in src
    assert "settings.litellm_key" in src


def _load_settings_class():
    """Load app.config in isolation.

    A plain `from app.config import Settings` passes alone and fails in the full run:
    other tests exec modules with stubs and leak them into sys.modules (the same leak
    that keeps test_ws_* excluded from CI). Loading from the file directly makes this
    guard independent of suite ordering.
    """
    import importlib.util

    spec = importlib.util.spec_from_file_location(
        "_spend_cfg_probe", API_ROOT / "app" / "config.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod.Settings


def test_settings_names_match_what_the_deploy_template_writes():
    """Cross-copy guard: pydantic field + LAMWARE_ prefix must equal the env file key."""
    Settings = _load_settings_class()

    prefix = Settings.model_config["env_prefix"]
    env_tmpl = (REPO_ROOT / "ansible" / "roles" / "api" / "templates"
                / "lamware-api.env.j2").read_text()

    for field in ("litellm_url", "litellm_key"):
        assert field in Settings.model_fields, f"settings lost field {field}"
        expected = f"{prefix}{field}".upper()
        assert re.search(rf"^{expected}=", env_tmpl, re.MULTILINE), (
            f"template does not write {expected}, which is the name settings reads")


def test_litellm_key_is_not_silently_defaulted_in_templates():
    """A missing vault var must fail the deploy, not ship a working default credential."""
    offenders = []
    for tmpl in (REPO_ROOT / "ansible").rglob("*.j2"):
        text = tmpl.read_text(errors="ignore")
        if re.search(r"litellm_master_key\s*\|\s*default\(", text):
            offenders.append(str(tmpl.relative_to(REPO_ROOT)))
    assert not offenders, (
        f"litellm_master_key is defaulted in {offenders}; use `| mandatory` so a missing "
        f"vault variable fails loudly instead of deploying a known default credential.")


def test_unreachable_upstream_is_logged_not_swallowed():
    """A bare `except Exception: return zeros` makes breakage look like free inference."""
    src = SPEND.read_text()
    assert "log.warning" in src or "log.error" in src, (
        "the LiteLLM failure path must log; a silent $0 is indistinguishable from "
        "genuinely free local inference")
