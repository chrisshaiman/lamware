# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""The Mythos 5.1 arm reaches Claude Platform on AWS only through the SigV4 forwarder.

Renders the real LiteLLM template with the role's defaults and parses the Ansible role,
asserting on structure rather than text (ADR-026):

  - no model_list entry for a model the forwarder signs for names a key: it points at
    the loopback forwarder with a placeholder the forwarder drops. The checker is also
    run against synthetic bad entries, so a checker that matches nothing fails here;
  - LiteLLM's forwarder base and the forwarder's listen port agree, and the alias's
    model is one the forwarder will sign for;
  - the CA's private key is used only on the controller (delegate_to: localhost) and
    no task copies it to the host; the host's key stays on the host and reaches the
    service only through systemd LoadCredential;
  - the role is in site.yml and off by default.

Structural, because these are deploy-time properties no runtime test on this machine
reaches; the forwarder's behaviour is in test_claude_platform_aws_forwarder.py.
"""

from pathlib import Path

import pytest

yaml = pytest.importorskip("yaml")
jinja2 = pytest.importorskip("jinja2")

ROOT = Path(__file__).resolve().parents[1]
LITELLM = ROOT / "ansible/roles/litellm"
ROLE = ROOT / "ansible/roles/claude-platform-aws"
DEFAULTS = yaml.safe_load((LITELLM / "defaults/main.yml").read_text()) or {}
ROLE_DEFAULTS = yaml.safe_load((ROLE / "defaults/main.yml").read_text()) or {}
PLACEHOLDER = "sk-claude-platform-aws-placeholder"


def _render_config() -> dict:
    env = jinja2.Environment(undefined=jinja2.StrictUndefined)
    env.filters.setdefault("mandatory", lambda v: v)
    text = (LITELLM / "templates/config.yaml.j2").read_text()
    return yaml.safe_load(env.from_string(text).render(
        **{**DEFAULTS, "litellm_master_key": "test-key"}))


def _signed_entries(model_list: list[dict]) -> list[dict]:
    signed = set(ROLE_DEFAULTS["claude_platform_aws_allowed_models"])
    return [m for m in model_list
            if m["model_name"] == "eval-mythos"
            or m["litellm_params"].get("model", "").removeprefix("anthropic/") in signed]


def _violations(model_list: list[dict]) -> list[str]:
    """Entries for a forwarded model that carry a key or bypass the forwarder."""
    base = DEFAULTS["litellm_claude_platform_aws_base"]
    bad = []
    for m in _signed_entries(model_list):
        p = m["litellm_params"]
        if p.get("api_key") != PLACEHOLDER:
            bad.append(f"{m['model_name']}: api_key {p.get('api_key')!r}")
        if p.get("api_base") != base:
            bad.append(f"{m['model_name']}: api_base {p.get('api_base')!r} is not {base}")
    return bad


def test_the_only_forwarded_entry_carries_no_key():
    cfg = _render_config()
    assert [m["model_name"] for m in _signed_entries(cfg["model_list"])] == [
        "eval-mythos", "eval-mythos52", "eval-fable52"]
    assert _violations(cfg["model_list"]) == []


@pytest.mark.parametrize("bad", [
    {"model_name": "eval-mythos", "litellm_params": {
        "model": "anthropic/claude-mythos-5-1",
        "api_key": "os.environ/ANTHROPIC_RESEARCH_API_KEY"}},
    {"model_name": "eval-mythos", "litellm_params": {
        "model": "anthropic/claude-mythos-5-1", "api_key": PLACEHOLDER}},
    {"model_name": "some-other-alias", "litellm_params": {
        "model": "anthropic/claude-mythos-5-1", "api_base": "http://127.0.0.1:4010",
        "api_key": "os.environ/ANTHROPIC_API_KEY"}},
])
def test_the_checker_catches_a_key_or_a_bypass(bad):
    """Guards the guard: a keyed Mythos entry, one that skips the forwarder, and a
    second alias for the same model must each be reported."""
    assert _violations([bad])


def test_litellm_points_at_the_port_the_forwarder_listens_on():
    host_port = DEFAULTS["litellm_claude_platform_aws_base"].removeprefix("http://")
    assert host_port == (f"{ROLE_DEFAULTS['claude_platform_aws_listen_host']}:"
                         f"{ROLE_DEFAULTS['claude_platform_aws_listen_port']}")


def test_every_forwarded_alias_model_is_one_the_forwarder_signs_for():
    """Both directions: an alias whose model the forwarder refuses fails at run time;
    an allowlisted model with no forwarded alias is CVP access nothing should use."""
    forwarded = {m["litellm_params"]["model"].removeprefix("anthropic/")
                 for m in _render_config()["model_list"]
                 if m["litellm_params"].get("api_base") == DEFAULTS["litellm_claude_platform_aws_base"]}
    assert forwarded == set(ROLE_DEFAULTS["claude_platform_aws_allowed_models"])


def test_the_role_is_off_by_default_and_in_site_yml():
    assert ROLE_DEFAULTS["claude_platform_aws_enabled"] is False
    plays = yaml.safe_load((ROOT / "ansible/site.yml").read_text())
    roles = [r["role"] if isinstance(r, dict) else r
             for p in plays for r in p.get("roles", [])]
    assert "claude-platform-aws" in roles


def _tasks(tasks=None):
    tasks = tasks if tasks is not None else yaml.safe_load((ROLE / "tasks/main.yml").read_text())
    for t in tasks:
        yield t
        yield from _tasks(t.get("block", []))


META = {"name", "when", "register", "delegate_to", "become", "notify", "loop",
        "changed_when", "failed_when", "block", "tags"}


def _module(task: dict) -> tuple[str, object]:
    (key,) = [k for k in task if k not in META]
    return key, task[key]


def test_the_ca_key_is_used_only_on_the_controller():
    """Anchored on what a task DOES with the path (module parameters and loop items),
    not on prose: an assert whose message names ca.key is not a use of it."""
    uses = [t for t in _tasks() if "block" not in t
            and _module(t)[0] != "ansible.builtin.assert"
            and "ca.key" in yaml.safe_dump([_module(t)[1], t.get("loop")])]
    assert uses, "no task signs with the CA: the checker would pass vacuously"
    for t in uses:
        assert t.get("delegate_to") == "localhost", f"{t['name']} touches ca.key on the host"
        assert not any(k.endswith((".copy", ".template")) for k in t), t["name"]


def test_the_host_key_reaches_the_services_only_through_loadcredential():
    for unit in ("claude-platform-aws.service.j2", "claude-platform-aws-check.service.j2"):
        text = (ROLE / "templates" / unit).read_text()
        lines = [ln for ln in text.splitlines() if not ln.lstrip().startswith("#")]
        assert any(ln.startswith("LoadCredential=host.key:") for ln in lines), unit
        assert not any("Environment=" in ln and "AWS_" in ln for ln in lines), unit
    key_task = next(t for t in _tasks() if "openssl_privatekey" in str(list(t)))
    params = key_task["community.crypto.openssl_privatekey"]
    assert (params["owner"], params["mode"], params["regenerate"]) == ("root", "0400", "never")
