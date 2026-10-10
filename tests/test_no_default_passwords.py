# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""No secret falls back to a literal default (M19).

Structural, because the property is "a missing vault value stops the deploy":
`default('changeme')` and `default('litellm')` created real database roles with
guessable passwords whenever the vault value was absent, silently.
"""
import re
from pathlib import Path

ROLES = Path(__file__).resolve().parents[1] / "ansible" / "roles"
SECRET = re.compile(r"\{\{\s*(\w*(?:password|passwd|secret|_key|token)\w*)\s*\|\s*default\(\s*['\"]([^'\"]+)['\"]",
                    re.IGNORECASE)


def test_no_secret_has_a_literal_default():
    hits = []
    for p in ROLES.rglob("*"):
        if p.suffix not in (".yml", ".yaml", ".j2") or "/packer/" in str(p):
            continue
        for n, line in enumerate(p.read_text(errors="ignore").splitlines(), 1):
            if line.lstrip().startswith("#"):
                continue
            for var, val in SECRET.findall(line):
                hits.append(f"{p.relative_to(ROLES)}:{n} {var} | default('{val}')")
    assert not hits, "secrets with a literal fallback:\n" + "\n".join(hits)


def test_the_cape_db_password_comes_from_the_vault():
    creds = (ROLES / "cape" / "tasks" / "credentials.yml").read_text()
    assert "cape_db_password | mandatory" in creds
    assert "lookup('ansible.builtin.password'" not in creds, "no generated password any more"
