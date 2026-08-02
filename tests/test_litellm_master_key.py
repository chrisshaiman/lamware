# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""Static guards for the LiteLLM master key (#238).

`litellm_master_key` authenticates every component to the LLM router. It was defined as
a role default and published in a public repo, which also made the three `| mandatory`
guards at the call sites unfirable — a role default satisfies `mandatory`, so a guard
that read as enforcement enforced nothing.

These are cheap static checks over the deploy tree. They cannot prove the deployed key
was rotated; they prove the repo cannot ship a working one again.
"""
import re
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
ANSIBLE = _ROOT / "ansible"
WRAPPER = ANSIBLE / "roles" / "interpret" / "templates" / "run-interpret-wrapper.sh.j2"
SECRETS_EXAMPLE = ANSIBLE / "vars" / "secrets.yml.example"
SITE_YML = ANSIBLE / "site.yml"
API_CONFIG = _ROOT / "api" / "app" / "config.py"

# The key that shipped. Split so this file does not itself contain the literal that
# gitleaks and any future grep for the retired credential are looking for.
RETIRED = "sk-" + "lamware"


def test_no_role_default_defines_the_master_key():
    """A role default satisfies `| mandatory`, so defining one disarms every call site."""
    offenders = []
    for path in ANSIBLE.rglob("*.yml"):
        if path.name.endswith(".example"):
            continue
        # Only defaults/ and vars/ actually DEFINE variables; tasks referencing the name
        # are fine and are covered by the `| default(` guard in api/tests.
        if path.parent.name not in ("defaults", "vars"):
            continue
        if path.parent == ANSIBLE / "vars":
            continue  # vars/secrets.yml is the vault, and is gitignored anyway
        if re.search(r"^\s*litellm_master_key\s*:", path.read_text(errors="ignore"), re.M):
            offenders.append(str(path.relative_to(_ROOT)))
    assert not offenders, (
        f"litellm_master_key is defined in {offenders}. A role default satisfies "
        f"`| mandatory`, so this silently re-disarms the guards at every call site — "
        f"the original #238 bug. It must come from vars/secrets.yml (vault) only.")


def test_retired_default_key_is_gone_from_the_tree():
    """The published credential must not survive anywhere — including in prose.

    Scans .md too. README.md documented the key by value, which is how a credential
    outlives its removal from code: the grep that proves the fallback is gone comes back
    clean while the string is still sitting in the docs of a public repo.

    Only this file is exempt, and only because it must name what it is looking for.
    """
    offenders = []
    for pattern in ("*.yml", "*.yaml", "*.j2", "*.py", "*.sh", "*.md", "*.ts", "*.tsx"):
        for path in _ROOT.rglob(pattern):
            if any(part in path.parts for part in
                   (".git", ".venv", "node_modules", "__pycache__", "dist", "build")):
                continue
            if path.resolve() == Path(__file__).resolve():
                continue
            if RETIRED in path.read_text(errors="ignore"):
                offenders.append(str(path.relative_to(_ROOT)))
    assert not offenders, (
        f"the retired default LiteLLM key still appears in {offenders}; it is published "
        f"in a public repo and must not remain as a fallback or in documentation.")


def test_api_config_does_not_default_the_key():
    """Empty fails closed; a real value here is a shared credential in a public repo."""
    src = API_CONFIG.read_text()
    match = re.search(r"^\s*litellm_key\s*:\s*str\s*=\s*(.+)$", src, re.M)
    assert match, "api/app/config.py lost the litellm_key field"
    assert match.group(1).strip() in ('""', "''"), (
        f"litellm_key defaults to {match.group(1).strip()}; it must default to empty so "
        f"an unconfigured API fails closed instead of authenticating with a known key.")


def test_interpret_wrapper_keeps_the_key_out_of_podman_argv():
    """/proc/<pid>/cmdline is world-readable — an inline value leaks to `ps`."""
    text = WRAPPER.read_text()
    assert not re.search(r'-e\s+LITELLM_API_KEY\s*=', text), (
        "the interpret wrapper passes LITELLM_API_KEY inline in podman's argv, which is "
        "visible to any local user via `ps` for the life of the run. Export it and "
        "forward it by name (`-e LITELLM_API_KEY`) instead.")
    assert re.search(r'-e\s+LITELLM_API_KEY\s*\\', text), (
        "the interpret wrapper must still forward LITELLM_API_KEY by name")
    assert "export LITELLM_API_KEY=" in text, (
        "forwarding by name only works if the key is exported into the wrapper's env")


def test_templates_that_render_the_key_suppress_diff():
    """`--diff` prints the whole rendered body, key included, unless the task opts out.

    Deliberately `diff: false` and NOT `no_log: true`. Measured: with the variable
    undefined, a no_log task reports

        FAILED! => {"censored": "the output has been hidden ..."}

    while a diff:false task reports

        FAILED! => {"msg": "... Mandatory variable 'litellm_master_key' not defined."}

    Both keep the key out of --diff. Only one of them leaves the guard legible when it
    fires, and an illegible guard is the whole complaint in #238.
    """
    rendering = {}
    for path in ANSIBLE.rglob("*.j2"):
        if "litellm_master_key" in path.read_text(errors="ignore"):
            rendering[path.name] = path
    assert rendering, "expected at least one template to render litellm_master_key"

    offenders = []
    for name, tmpl_path in rendering.items():
        tasks = tmpl_path.parent.parent / "tasks" / "main.yml"
        if not tasks.exists():
            continue
        text = tasks.read_text(errors="ignore")
        block = re.search(rf"src:\s*{re.escape(name)}\b(.*?)(?=\n- name:|\Z)", text, re.S)
        if not block:
            continue
        body = block.group(1)
        if not re.search(r"^\s*diff:\s*(false|no)\s*$", body, re.M):
            offenders.append(f"{tasks.relative_to(_ROOT)} (src: {name})")

    assert not offenders, (
        f"these tasks render litellm_master_key into a file without `diff: false`: "
        f"{offenders}. Running the play with --diff would print the key.")


def test_secrets_example_documents_the_key():
    """An operator following the documented setup must be prompted to set it."""
    text = SECRETS_EXAMPLE.read_text()
    assert re.search(r"^\s*litellm_master_key\s*:", text, re.M), (
        "vars/secrets.yml.example must list litellm_master_key — without it, an operator "
        "following DEPLOYMENT.md has nothing telling them the variable exists.")
    assert "secrets.token_urlsafe" in text or "token_hex" in text, (
        "secrets.yml.example should carry a generation command for the key")


def test_site_yml_rejects_an_empty_key_even_on_a_tagged_deploy():
    """The empty-key check must survive `--tags`, because a rotation IS a tagged deploy.

    Two gaps compound without this. pre_tasks are skipped unless tagged `always`, and
    `| mandatory` at the call sites fires only on UNDEFINED, never on empty. Measured
    with an empty key and `--tags litellm`: the assert is skipped, the template renders
    `master_key: ""`, and the play reports ok=1 failed=0.

    So it is not enough for the check to exist — it has to be in a task carrying the
    `always` tag.
    """
    text = SITE_YML.read_text()
    assert "litellm_master_key" in text, (
        "site.yml must assert litellm_master_key is non-empty; `| mandatory` at the "
        "call sites cannot catch a copied-but-unfilled example.")

    # Find the assert task that mentions the key and confirm it is tagged `always`.
    tasks = re.split(r"\n(?=\s*- name:)", text)
    owning = [t for t in tasks
              if "litellm_master_key" in t and "assert" in t and "length > 0" in t]
    assert owning, "no assert task checks litellm_master_key | length > 0"
    assert any(re.search(r"tags:\s*\[[^\]]*\balways\b", t) for t in owning), (
        "the litellm_master_key assert must be tagged `always`. Without it, "
        "`make deploy TAGS=litellm,...` — the rotation path — skips the check and "
        "renders an empty master key into LiteLLM's config, reporting success.")
