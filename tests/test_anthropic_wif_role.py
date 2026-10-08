# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""The anthropic-wif role renders a config the forwarder accepts only when it should.

Behavioural where it can be: the real config.json.j2 is rendered with the role's
defaults and fed to the forwarder's own load_config. With the defaults (no Console
ids) the service must refuse to start and name every missing id; with ids filled in it
must load, bound to loopback.

The systemd unit checks are STRUCTURAL (parsed key/value, not regex over text): nothing
on a developer machine can run the unit under systemd's sandbox, and these are the
properties the PR claims. They say what the unit asks for, not that the host honours it.
"""

import json
import sys
from pathlib import Path

import pytest

yaml = pytest.importorskip("yaml")
jinja2 = pytest.importorskip("jinja2")
pytest.importorskip("cryptography")

ROOT = Path(__file__).resolve().parents[1]
ROLE = ROOT / "ansible/roles/anthropic-wif"
DEFAULTS = yaml.safe_load((ROLE / "defaults/main.yml").read_text())
sys.path.insert(0, str(ROLE / "files"))
import anthropic_wif as wif  # noqa: E402


def _env() -> jinja2.Environment:
    env = jinja2.Environment(undefined=jinja2.StrictUndefined)
    env.filters["to_nice_json"] = lambda v: json.dumps(v, indent=4, sort_keys=True)
    return env


def _resolve(vars_: dict) -> dict:
    """Template the defaults against themselves until stable, as Ansible would lazily."""
    out = dict(vars_)
    for _ in range(5):
        out = {k: _env().from_string(v).render(**out) if isinstance(v, str) else v
               for k, v in out.items()}
    return out


def _render(name: str, **overrides) -> str:
    v = _resolve({**DEFAULTS, "lamware_domain": "lamware.example.test", **overrides})
    return _env().from_string((ROLE / "templates" / name).read_text()).render(**v)


def test_defaults_render_a_config_the_service_refuses(tmp_path):
    p = tmp_path / "config.json"
    p.write_text(_render("config.json.j2"))
    with pytest.raises(wif.ConfigError) as exc:
        wif.load_config(str(p), environ={})
    for key in ("organization_id", "workspace_id", "service_account_id", "federation_rule_id"):
        assert key in str(exc.value)


def test_filled_ids_render_a_loopback_config(tmp_path):
    p = tmp_path / "config.json"
    p.write_text(_render("config.json.j2", anthropic_wif_organization_id="o",
                         anthropic_wif_workspace_id="w", anthropic_wif_service_account_id="s",
                         anthropic_wif_federation_rule_id="r"))
    cfg = wif.load_config(str(p), environ={})
    assert cfg.listen_host == "127.0.0.1" and cfg.listen_port == 4010
    assert cfg.expected_issuer == "https://lamware.example.test/auth/realms/lamware"
    assert cfg.keycloak_token_url == ("http://127.0.0.1:8080/auth/realms/lamware/protocol/"
                                      "openid-connect/token")
    assert cfg.allowed_models == ("claude-mythos-5-1",)
    assert cfg.allowed_peer_uids == (0,)
    assert cfg.anthropic_token_url == "https://api.anthropic.com/v1/oauth/token"
    # The Console ids are not defaulted anywhere in the repo (they identify the org).
    assert all(DEFAULTS[k] == "" for k in DEFAULTS if k.endswith("_id")
               and k != "anthropic_wif_client_id")


def _unit(name: str) -> dict[str, list[str]]:
    kv: dict[str, list[str]] = {}
    for line in _render(name).splitlines():
        if "=" in line and not line.lstrip().startswith(("#", "[")):
            k, v = line.split("=", 1)
            kv.setdefault(k.strip(), []).append(v.strip())
    return kv


@pytest.mark.parametrize("name", ["anthropic-wif.service.j2", "anthropic-wif-kidcheck.service.j2"])
def test_units_run_unprivileged_and_sandboxed(name):
    u = _unit(name)
    assert u["User"] == ["anthropic-wif"]
    for key, val in {"NoNewPrivileges": "yes", "ProtectSystem": "strict", "PrivateTmp": "yes",
                     "ProtectHome": "yes", "CapabilityBoundingSet": ""}.items():
        assert u[key] == [val], key
    assert u["LoadCredential"] == ["client-key.pem:/etc/anthropic-wif/client-key.pem"]
    # /proc/net/tcp must stay visible for the peer-uid check.
    assert "ProcSubset" not in u and "PrivateNetwork" not in u


def test_forwarder_config_errors_do_not_restart_loop():
    u = _unit("anthropic-wif.service.j2")
    assert u["RestartPreventExitStatus"] == [str(wif.EXIT_CONFIG)]
