#!/usr/bin/env python3
# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""Set the deployment's default LLM profile (ADR-038): `make llm-default PROFILE=NAME`.

Checks NAME against the profiles a deploy would render (`local`, the role's built-ins,
and the operator's `pipeline_llm_profiles`), then sets `pipeline_default_llm_profile`
in ansible/vars/main.yml, changing that one line and nothing else in the file. The
Makefile then deploys the pipeline role. Prints only profile names, never other values.

Exit 2 on a name that is not defined, or on a vars file this cannot edit safely
(vault-encrypted, or not a YAML mapping).
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
DEFAULTS = ROOT / "ansible/roles/pipeline/defaults/main.yml"
VARS = ROOT / "ansible/vars/main.yml"
KEY = "pipeline_default_llm_profile"
LINE = re.compile(rf"^{KEY}\s*:.*$", re.M)


def defined_profiles(defaults: Path, vars_file: Path) -> dict[str, dict]:
    """name -> profile, as config.json.j2 merges them; `local` maps to {}."""
    builtin = (yaml.safe_load(defaults.read_text()) or {}).get("pipeline_llm_profiles_builtin") or {}
    own = {}
    if vars_file.exists():
        own = (yaml.safe_load(vars_file.read_text()) or {}).get("pipeline_llm_profiles") or {}
    return {"local": {}, **builtin, **own}


def set_default(name: str, defaults: Path = DEFAULTS, vars_file: Path = VARS) -> str:
    """Write `name` as the default and return the previous value (or the role's)."""
    text = vars_file.read_text() if vars_file.exists() else ""
    if text.lstrip().startswith("$ANSIBLE_VAULT"):
        raise SystemExit(f"{vars_file} is vault-encrypted; set {KEY}: {name} in it by hand")
    if text and not isinstance(yaml.safe_load(text) or {}, dict):
        raise SystemExit(f"{vars_file} is not a YAML mapping; set {KEY}: {name} by hand")
    profiles = defined_profiles(defaults, vars_file)
    if name not in profiles:
        print(f"'{name}' is not a defined LLM profile; defined: {', '.join(profiles)}", file=sys.stderr)
        raise SystemExit(2)
    before = (yaml.safe_load(text) or {}).get(KEY) if text else None
    before = before or (yaml.safe_load(defaults.read_text()) or {}).get(KEY, "local")
    if LINE.search(text):
        text = LINE.sub(f"{KEY}: {name}", text, count=1)
    else:
        text += ("" if text.endswith("\n") or not text else "\n") + (
            f"\n# The profile every run without --llm-profile uses (ADR-038); "
            f"`make llm-default PROFILE=...` sets it.\n{KEY}: {name}\n")
    vars_file.write_text(text)
    return before


def main(argv: list[str]) -> int:
    if len(argv) != 1 or not re.fullmatch(r"[a-z0-9-]+", argv[0]):
        print("usage: make llm-default PROFILE=NAME   (lowercase letters, digits, '-')", file=sys.stderr)
        return 2
    name = argv[0]
    before = set_default(name)
    prof = defined_profiles(DEFAULTS, VARS)[name]
    print(f"default LLM profile: {before} -> {name}  ({VARS.relative_to(ROOT)})")
    if prof.get("cloud") is True:
        print(f"NOTE: '{name}' is a CLOUD profile. After this deploy, every run without "
              f"--llm-profile (API submissions, the feeder, intake) sends prompts off the host.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
