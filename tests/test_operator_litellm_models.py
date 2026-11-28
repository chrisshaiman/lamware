"""The operator's own LiteLLM models reach LiteLLM and the pipeline (ADR-038, PR 7).

Renders the REAL templates with every role's defaults plus example operator entries:
  - each entry lands in LiteLLM's model_list exactly as given, after the built-ins;
  - its credentials reach the env file, and the config holds only os.environ/ refs;
  - the pipeline's config lists the `local: true` entries, and only those, as local.
The deploy-time checks (tasks/operator-models.yml) run under Ansible, not here.
"""
import json
from pathlib import Path

import pytest

yaml = pytest.importorskip("yaml")
jinja2 = pytest.importorskip("jinja2")

ROOT = Path(__file__).resolve().parents[1]
ROLES = ROOT / "ansible/roles"

MODELS = [
    {"model_name": "eval-bedrock-sonnet", "local": False,
     "litellm_params": {"model": "bedrock/anthropic.claude-sonnet-5-5", "aws_region_name": "us-east-1",
                        "aws_access_key_id": "os.environ/AWS_ACCESS_KEY_ID",
                        "aws_secret_access_key": "os.environ/AWS_SECRET_ACCESS_KEY"}},
    {"model_name": "local-ollama-qwen", "local": True,
     "litellm_params": {"model": "ollama/qwen3", "api_base": "http://127.0.0.1:11434"}},
]
ENV = {"AWS_ACCESS_KEY_ID": "AKIAEXAMPLE", "AWS_SECRET_ACCESS_KEY": "example-secret"}


def _ctx(**over):
    ctx = {}
    for r in ("interpret", "pipeline", "api", "litellm"):
        ctx.update(yaml.safe_load((ROLES / r / "defaults/main.yml").read_text()) or {})
    return {**ctx, "litellm_master_key": "k", "litellm_db_password": "p", **over}


def _env():
    env = jinja2.Environment(undefined=jinja2.ChainableUndefined)  # noqa: S701 - YAML/JSON, not HTML
    env.filters["mandatory"] = lambda v: "placeholder" if isinstance(v, jinja2.Undefined) else v
    # Values another role supplies at deploy (cape_api_url, ...) are irrelevant here.
    env.filters["to_json"] = lambda v: json.dumps("placeholder" if isinstance(v, jinja2.Undefined) else v)
    env.filters["combine"] = lambda a, *bs: {k: v for d in (a, *bs) for k, v in d.items()}
    env.tests["defined"] = lambda v: not isinstance(v, jinja2.Undefined)
    return env


def _render(rel, **over):
    return _env().from_string((ROLES / rel).read_text()).render(**_ctx(**over))


def test_operator_entries_land_in_the_model_list_as_given():
    cfg = yaml.safe_load(_render("litellm/templates/config.yaml.j2", litellm_operator_models=MODELS))
    by_name = {m["model_name"]: m for m in cfg["model_list"]}
    for m in MODELS:
        assert by_name[m["model_name"]]["litellm_params"] == m["litellm_params"]
    names = [m["model_name"] for m in cfg["model_list"]]
    assert len(names) == len(set(names))


def test_without_operator_entries_the_model_list_is_unchanged():
    base = yaml.safe_load(_render("litellm/templates/config.yaml.j2"))["model_list"]
    assert not any(m["model_name"] in {"eval-bedrock-sonnet", "local-ollama-qwen"} for m in base)


def test_credentials_go_to_the_env_file_and_the_config_holds_only_references():
    env_text = _render("litellm/templates/litellm.env.j2", litellm_operator_env=ENV,
                       litellm_anthropic_wif_routes=["eval", "production"])
    assert "AWS_ACCESS_KEY_ID=AKIAEXAMPLE" in env_text.splitlines()
    cfg_text = _render("litellm/templates/config.yaml.j2", litellm_operator_models=MODELS)
    assert "AKIAEXAMPLE" not in cfg_text and "example-secret" not in cfg_text


def test_the_pipeline_lists_only_the_local_entries_as_local():
    rendered = _render("pipeline/templates/config.json.j2", litellm_operator_models=MODELS)
    line = next(ln for ln in rendered.splitlines() if '"local_aliases"' in ln)
    assert json.loads("{" + line.strip().rstrip(",") + "}")["local_aliases"] == ["local-ollama-qwen"]
