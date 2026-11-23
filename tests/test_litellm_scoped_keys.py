# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""Every caller gets a scoped LiteLLM key; the master key stays in LiteLLM's files (V1).

The master key administers LiteLLM: it creates keys, reads every caller's spend,
and could re-route models. It was rendered into the interpret wrappers (group
lamware: readable by cape, auto-feeder and lamware-api), the digest and the API's
environment. lamware-litellm-keys keeps one scoped key per caller. It is run here
against a fake LiteLLM that answers the endpoints the way the host's 1.106.0 did
when probed (2026-11-15): a scoped key gets 401/403 on admin endpoints; a deleted
key is refused at once.
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import threading
import uuid
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
ANSIBLE = ROOT / "ansible"
LITELLM = ANSIBLE / "roles" / "litellm"
SCRIPT = LITELLM / "files" / "lamware-litellm-keys"
DEFAULTS = yaml.safe_load((LITELLM / "defaults" / "main.yml").read_text())
MASTER = "sk-master-test"


class FakeLiteLLM(BaseHTTPRequestHandler):
    keys: dict = {}      # key -> {"key_alias", "models", "user_id"}
    users: dict = {}     # user_id -> role
    calls: list = []

    def log_message(self, *a):  # quiet
        pass

    def _send(self, code, body):
        data = json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _auth(self):
        return self.headers.get("Authorization", "").removeprefix("Bearer ")

    def do_GET(self):
        u = urlparse(self.path)
        self.calls.append(("GET", u.path))
        if self._auth() != MASTER:
            return self._send(401, {})
        if u.path == "/key/info":
            k = parse_qs(u.query).get("key", [""])[0]
            if k not in self.keys:
                return self._send(404, {})
            return self._send(200, {"info": dict(self.keys[k])})
        self._send(404, {})

    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))) or b"{}")
        self.calls.append(("POST", self.path, body))
        if self._auth() != MASTER:
            return self._send(401, {})
        if self.path == "/key/generate":
            k = "sk-" + uuid.uuid4().hex
            self.keys[k] = {"key_alias": body["key_alias"], "models": body.get("models", []),
                            "user_id": body.get("user_id")}
            return self._send(200, {"key": k})
        if self.path == "/key/delete":
            for k in [k for k, v in self.keys.items() if v["key_alias"] in body.get("key_aliases", [])]:
                del self.keys[k]
            return self._send(200, {})
        if self.path == "/key/update":
            self.keys[body["key"]]["models"] = body["models"]
            return self._send(200, {})
        if self.path == "/user/new":
            uid = uuid.uuid4().hex
            self.users[uid] = body["user_role"]
            return self._send(200, {"user_id": uid})
        self._send(404, {})


@pytest.fixture
def litellm(tmp_path):
    FakeLiteLLM.keys, FakeLiteLLM.users, FakeLiteLLM.calls = {}, {}, []
    srv = HTTPServer(("127.0.0.1", 0), FakeLiteLLM)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    cfg = tmp_path / "config.yaml"
    cfg.write_text(yaml.safe_dump({"general_settings": {"master_key": MASTER}}))
    keys_dir = tmp_path / "keys"
    keys_dir.mkdir(mode=0o700)
    env = {"PATH": "/usr/bin:/bin", "LITELLM_CONFIG": str(cfg),
           "LITELLM_URL": f"http://127.0.0.1:{srv.server_port}",
           "LITELLM_KEYS_FILE": str(keys_dir / "keys.json")}
    yield env, keys_dir / "keys.json"
    srv.shutdown()


SPECS = [{"name": "interpret", "models": []},
         {"name": "digest", "models": ["local-qwen-llamacpp"]},
         {"name": "api-spend", "role": "proxy_admin_viewer", "models": ["no-models"]}]


def run(env, tmp_path, specs=SPECS):
    f = tmp_path / "specs.json"
    f.write_text(json.dumps(specs))
    r = subprocess.run([sys.executable, "-I", str(SCRIPT), str(f)], env=env,
                       capture_output=True, text=True, timeout=30)
    assert r.returncode == 0, r.stderr
    return json.loads(r.stdout), r.stdout + r.stderr


def test_first_run_creates_one_key_per_caller_and_prints_no_key(litellm, tmp_path):
    env, keys_file = litellm
    done, out = run(env, tmp_path)
    assert done == {"interpret": "created", "digest": "created", "api-spend": "created"}
    keys = json.loads(keys_file.read_text())
    assert set(keys) == {"interpret", "digest", "api-spend"}
    for k in keys.values():
        assert k not in out and MASTER not in out
        assert k != MASTER
    assert oct(keys_file.stat().st_mode & 0o777) == "0o600"
    aliases = {v["key_alias"]: v for v in FakeLiteLLM.keys.values()}
    assert aliases["lamware-digest"]["models"] == ["local-qwen-llamacpp"]
    assert aliases["lamware-interpret"]["models"] == []
    viewer = aliases["lamware-api-spend"]
    assert FakeLiteLLM.users[viewer["user_id"]] == "proxy_admin_viewer"


def test_a_second_run_keeps_everything_and_writes_nothing(litellm, tmp_path):
    env, keys_file = litellm
    run(env, tmp_path)
    before = keys_file.read_text()
    mtime = keys_file.stat().st_mtime_ns
    done, _ = run(env, tmp_path)
    assert set(done.values()) == {"kept"}
    assert keys_file.read_text() == before and keys_file.stat().st_mtime_ns == mtime


def test_a_changed_model_list_updates_the_same_key(litellm, tmp_path):
    env, keys_file = litellm
    run(env, tmp_path)
    old = json.loads(keys_file.read_text())["digest"]
    specs = [dict(s) for s in SPECS]
    specs[1]["models"] = ["claude-haiku-4-5"]
    done, _ = run(env, tmp_path, specs)
    assert done["digest"] == "updated"
    assert json.loads(keys_file.read_text())["digest"] == old
    assert FakeLiteLLM.keys[old]["models"] == ["claude-haiku-4-5"]


def test_a_key_litellm_no_longer_knows_is_replaced_and_the_alias_cleared(litellm, tmp_path):
    env, keys_file = litellm
    run(env, tmp_path)
    old = json.loads(keys_file.read_text())["interpret"]
    del FakeLiteLLM.keys[old]
    stray = "sk-stray"
    FakeLiteLLM.keys[stray] = {"key_alias": "lamware-interpret", "models": [], "user_id": None}
    done, _ = run(env, tmp_path)
    assert done["interpret"] == "created"
    new = json.loads(keys_file.read_text())["interpret"]
    assert new != old and new in FakeLiteLLM.keys
    assert stray not in FakeLiteLLM.keys, "an old key under the alias was left valid"


def test_a_key_under_another_alias_is_not_trusted(litellm, tmp_path):
    env, keys_file = litellm
    run(env, tmp_path)
    keys = json.loads(keys_file.read_text())
    FakeLiteLLM.keys[keys["digest"]]["key_alias"] = "someone-else"
    done, _ = run(env, tmp_path)
    assert done["digest"] == "created"


# --- the deployed shape ---------------------------------------------------------------

def test_the_specs_scope_each_caller():
    specs = {s["name"]: s for s in DEFAULTS["litellm_scoped_keys"]}
    assert specs["interpret"]["models"] == []
    assert specs["digest"]["models"] == ["{{ interpret_summary_model | default('local-qwen-llamacpp') }}"]
    assert specs["api-spend"] == {"name": "api-spend", "role": "proxy_admin_viewer", "models": ["no-models"]}


def test_the_master_key_is_rendered_only_by_the_litellm_role():
    offenders = []
    for path in ANSIBLE.rglob("*"):
        if path.is_file() and path.suffix in (".j2", ".yml") and "litellm_master_key" in path.read_text(errors="ignore"):
            rel = path.relative_to(ANSIBLE)
            if rel.parts[:2] == ("roles", "litellm") or rel == Path("site.yml"):
                continue
            # A comment naming the variable is not a use.
            uses = [ln for ln in path.read_text().splitlines()
                    if "litellm_master_key" in ln and not ln.lstrip().startswith(("#", "{#"))]
            if uses:
                offenders.append(f"{rel}: {uses[0].strip()[:80]}")
    assert not offenders, offenders


@pytest.mark.parametrize("role, before", [
    ("interpret", "Deploy interpret wrapper script"),
    ("ntfy-alerts", "Deploy daily digest script"),
    ("api", "Deploy lamware-api environment file"),
])
def test_each_caller_imports_the_keys_before_it_renders_one(role, before):
    tasks = yaml.safe_load((ANSIBLE / "roles" / role / "tasks" / "main.yml").read_text())
    names = [t.get("name") for t in tasks]
    i = names.index("Read the scoped LiteLLM keys")
    imp = tasks[i]["ansible.builtin.import_role"]
    assert imp == {"name": "litellm", "tasks_from": "read-keys"}, "import, so tags carry"
    assert i < names.index(before)


def test_only_pipeline_can_read_the_interpret_wrappers():
    tasks = yaml.safe_load((ANSIBLE / "roles" / "interpret" / "tasks" / "main.yml").read_text())
    for name in ("Deploy interpret wrapper script", "Deploy prompt A/B wrapper"):
        t = next(x for x in tasks if x.get("name") == name)["ansible.builtin.template"]
        assert (t["owner"], t["group"], t["mode"]) == ("root", "pipeline", "0750"), name


def test_the_key_file_is_root_only_and_the_manager_prints_no_secret():
    tasks = yaml.safe_load((LITELLM / "tasks" / "main.yml").read_text())
    d = next(t for t in tasks if t.get("name") == "Create the scoped-key directory (root only)")
    assert d["ansible.builtin.file"]["mode"] == "0700"
    rk = yaml.safe_load((LITELLM / "tasks" / "read-keys.yml").read_text())
    secret = [t for t in rk if "ansible.builtin.slurp" in t or "ansible.builtin.set_fact" in t]
    assert len(secret) == 2 and all(t.get("no_log") is True for t in secret)
    assert os.access(SCRIPT, os.X_OK)
    assert re.search(r"print\(json\.dumps\(done", SCRIPT.read_text())


# --- check 24, run for real against fixture trees ---------------------------------------

SMOKE = (ANSIBLE / "roles/security-test/templates/security-smoke-test.sh.j2").read_text()
CHECK24 = SMOKE[SMOKE.index('echo "[24/27]'):SMOKE.index('echo "[25/27]')]


def _check24(tmp_path, files: dict[str, str], config=True) -> str:
    llm = tmp_path / "litellm"
    llm.mkdir()
    if config:
        (llm / "config.yaml").write_text(yaml.safe_dump({"general_settings": {"master_key": MASTER}}))
    other = tmp_path / "opt"
    other.mkdir()
    shm = tmp_path / "shm"
    shm.mkdir()
    for rel, text in files.items():
        f = other / rel
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_text(text)
    body = (CHECK24.replace("{{ litellm_install_dir | default('/opt/litellm') }}", str(llm))
            .replace('LLM_ROOTS="/opt /etc /usr/local /var/lib /home /root /srv"',
                     f'LLM_ROOTS="{llm} {other}"')
            # Outside the searched roots, as /dev/shm is on the host.
            .replace("mktemp -p /dev/shm", f"mktemp -p {shm}"))
    script = 'pass() { echo "PASS: $1"; }\nfail() { echo "FAIL: $1"; }\n' + body
    return subprocess.run(["bash", "-c", script], capture_output=True, text=True, timeout=60).stdout


def test_check24_passes_when_only_litellm_holds_the_key(tmp_path):
    out = _check24(tmp_path, {"interpret/run-interpret": "export LITELLM_API_KEY=sk-scoped\n"})
    assert out.strip().endswith(f"PASS: LiteLLM master key: only in {tmp_path}/litellm"), out


def test_check24_names_a_copy_outside_litellm(tmp_path):
    out = _check24(tmp_path, {"interpret/run-interpret": f"export LITELLM_API_KEY={MASTER}\n"})
    assert "FAIL: the LiteLLM master key is outside LiteLLM's files:" in out
    assert "interpret/run-interpret" in out and MASTER not in out


def test_check24_is_blind_without_litellms_config(tmp_path):
    out = _check24(tmp_path, {}, config=False)
    assert "FAIL: master-key probe is blind" in out


def test_a_non_http_litellm_url_is_refused(tmp_path):
    f = tmp_path / "specs.json"
    f.write_text("[]")
    r = subprocess.run([sys.executable, "-I", str(SCRIPT), str(f)],
                       env={"PATH": "/usr/bin:/bin", "LITELLM_URL": "file:///etc/shadow"},
                       capture_output=True, text=True, timeout=30)
    assert r.returncode != 0 and "must be http(s)" in r.stderr


def test_the_investigate_key_allows_exactly_the_agents_allowlist():
    """VALID_MODELS = sorted(MODEL_COSTS). A model added there and not here would be
    refused by LiteLLM; one here and not there is spend the agent can't account for."""
    import ast
    tree = ast.parse((ROOT / "api/app/investigate/orchestrator.py").read_text())
    costs = next(n.value for n in ast.walk(tree)
                 if isinstance(n, ast.AnnAssign) and getattr(n.target, "id", "") == "MODEL_COSTS")
    allowed = sorted(k.value for k in costs.keys)
    spec = next(s for s in DEFAULTS["litellm_scoped_keys"] if s["name"] == "investigate")
    assert sorted(spec["models"]) == allowed


def test_every_settings_key_the_api_sends_has_its_own_scoped_key():
    """The miss that made this test: the API sent settings.litellm_key from two places,
    and V1 scoped it for one of them. Each settings field the API sends to LiteLLM
    must be written by the env template from a scoped key."""
    import re as _re
    sent = set()
    for py in (ROOT / "api" / "app").rglob("*.py"):
        sent |= set(_re.findall(r"Bearer \{settings\.(litellm_\w+)\}", py.read_text()))
    env = (ANSIBLE / "roles/api/templates/lamware-api.env.j2").read_text()
    assert sent == {"litellm_key", "litellm_investigate_key"}, sent
    for field in sent:
        line = next(ln for ln in env.splitlines() if ln.startswith(f"LAMWARE_{field.upper()}="))
        assert "litellm_scoped" in line, line
