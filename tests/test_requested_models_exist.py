# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""Every model name the interpret container or the pipeline can REQUEST exists in LiteLLM.

#643 removed the `local-qwen` aliases from LiteLLM. The legacy synthesis fallback
in interpret-ghidra.py still requested `model="local-qwen"`, so it failed in 0.5 s
every time it ran, and the one path that exists to rescue a runaway synthesis
could never rescue anything (#675: formbook, dotnet-agentic-vs-ss-2610). #643's
Scope enumerated config defaults and research-script defaults, not literals in
code; test_every_arm_model_has_a_litellm_entry covers eval arms only.

Structural, because no runtime test reaches a fallback that only fires after a
runaway synthesis. It renders the real LiteLLM template with the role's own
defaults (not a substring search) and collects literals the code would send:
`model=` keyword arguments, `"<...>model"` dict entries, and
`.get("<...>model", "<default>")` fallbacks.
"""
import ast
from pathlib import Path

import pytest

yaml = pytest.importorskip("yaml")
jinja2 = pytest.importorskip("jinja2")

ROOT = Path(__file__).resolve().parents[1]
LITELLM = ROOT / "ansible/roles/litellm"
SENDERS = [ROOT / "ansible/roles/interpret/files/interpret-ghidra.py",
           ROOT / "ansible/roles/pipeline/files/run-pipeline.py",
           *sorted((ROOT / "ansible/roles/pipeline/files/stages").glob("*.py"))]


def _registered_models() -> set[str]:
    defaults = yaml.safe_load((LITELLM / "defaults/main.yml").read_text()) or {}
    env = jinja2.Environment(undefined=jinja2.StrictUndefined)
    env.filters.setdefault("mandatory", lambda v: v)
    text = env.from_string((LITELLM / "templates/config.yaml.j2").read_text()).render(
        **defaults, litellm_master_key="test-key")
    cfg = yaml.safe_load(text)
    return {m["model_name"] for m in cfg["model_list"]}


def _is_model_key(k: object) -> bool:
    return isinstance(k, str) and k.endswith("model") and not k.startswith("_")


def _requested_literals() -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    for path in SENDERS:
        rel = path.relative_to(ROOT)
        for n in ast.walk(ast.parse(path.read_text())):
            if isinstance(n, ast.Call):
                for kw in n.keywords:
                    if kw.arg == "model" and isinstance(kw.value, ast.Constant) \
                            and isinstance(kw.value.value, str):
                        out.append((kw.value.value, f"{rel}:{n.lineno} model="))
                if (isinstance(n.func, ast.Attribute) and n.func.attr == "get"
                        and len(n.args) == 2 and isinstance(n.args[0], ast.Constant)
                        and _is_model_key(n.args[0].value)
                        and isinstance(n.args[1], ast.Constant)
                        and isinstance(n.args[1].value, str)):
                    out.append((n.args[1].value, f"{rel}:{n.lineno} .get({n.args[0].value!r})"))
            elif isinstance(n, ast.Dict):
                for k, v in zip(n.keys, n.values):
                    if isinstance(k, ast.Constant) and _is_model_key(k.value) \
                            and isinstance(v, ast.Constant) and isinstance(v.value, str) and v.value:
                        out.append((v.value, f"{rel}:{v.lineno} {k.value!r}:"))
    return out


# Values that are not model aliases sent to LiteLLM.
NOT_A_REQUEST = {
    "none",   # interpret-ghidra.py: "model_used": "none" on the no-API-key error path
    "?", "",  # run-pipeline.py: display placeholders in log lines (.get("model", "?"))
}


def test_the_probe_sees_the_template_and_the_code():
    models = _registered_models()
    assert "local-qwen-llamacpp-re" in models and "haiku-fallback" in models, models
    assert len(_requested_literals()) >= 3, "the scan found almost nothing: the probe is broken"


def test_every_requested_model_is_registered():
    models = _registered_models()
    missing = sorted({f"{name}  <- {where}" for name, where in _requested_literals()
                      if name not in models and name not in NOT_A_REQUEST})
    assert not missing, ("code requests models LiteLLM does not serve:\n  "
                         + "\n  ".join(missing))
