# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""CAPE's web UI needs a login (V13).

The middleware is run against stand-ins for Django's LoginRequiredMiddleware and
DRF's APIView (Django is not installed here); the host evidence is security-test
check 25, whose own shell block is also run here against a stub curl.
"""
from __future__ import annotations

import subprocess
import sys
import types
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
ROLE = ROOT / "ansible/roles/cape"
MIDDLEWARE = ROLE / "files/lamware_login.py"
TASKS = yaml.safe_load((ROLE / "tasks/web-login.yml").read_text())
SMOKE = (ROOT / "ansible/roles/security-test/templates/security-smoke-test.sh.j2").read_text()


@pytest.fixture
def mw(monkeypatch):
    class LoginRequiredMiddleware:
        def __init__(self, get_response=None):
            pass

        def process_view(self, request, view_func, view_args, view_kwargs):
            return "redirect-to-login"

    class APIView:
        pass

    for name, attrs in {
        "django": {}, "django.contrib": {}, "django.contrib.auth": {},
        "django.contrib.auth.middleware": {"LoginRequiredMiddleware": LoginRequiredMiddleware},
        "rest_framework": {}, "rest_framework.views": {"APIView": APIView},
    }.items():
        mod = types.ModuleType(name)
        mod.__dict__.update(attrs)
        monkeypatch.setitem(sys.modules, name, mod)
    ns: dict = {"__name__": "lamware_login"}
    exec(compile(MIDDLEWARE.read_text(), "lamware_login.py", "exec"), ns)  # noqa: S102
    ns["_APIView"] = APIView
    return ns


class Req:
    def __init__(self, path):
        self.path = path


def _view(cls=None):
    def view(request):
        return None
    if cls is not None:
        view.cls = cls
    return view


@pytest.mark.parametrize("path", ["/", "/analysis/", "/analysis/1321/", "/submit/",
                                  "/accounts/api-keys/", "/accounts/signup/", "/apiv2/",
                                  "/file/sample/1321/abc/", "/admin/"])
def test_every_page_needs_a_login(mw, path):
    m = mw["LamwareLoginRequired"]()
    assert m.process_view(Req(path), _view(), (), {}) == "redirect-to-login", path


@pytest.mark.parametrize("path", ["/accounts/login/", "/accounts/logout/", "/static/css/x.css"])
def test_the_login_page_and_static_files_stay_reachable(mw, path):
    m = mw["LamwareLoginRequired"]()
    assert m.process_view(Req(path), _view(), (), {}) is None


def test_rest_api_views_keep_their_own_token_authentication(mw):
    class TasksView(mw["_APIView"]):
        pass

    m = mw["LamwareLoginRequired"]()
    assert m.process_view(Req("/apiv2/tasks/view/1/"), _view(TasksView), (), {}) is None


def test_a_non_api_class_is_not_waved_through(mw):
    class NotAnAPIView:
        pass

    m = mw["LamwareLoginRequired"]()
    assert m.process_view(Req("/apiv2/tasks/view/1/"), _view(NotAnAPIView), (), {}) == "redirect-to-login"
    assert m.process_view(Req("/x/"), _view("not-a-class"), (), {}) == "redirect-to-login"


# --- the role ------------------------------------------------------------------------

def _task(name):
    return next(t for t in TASKS if t.get("name") == name)


def test_web_auth_is_on_and_the_middleware_is_installed():
    ini = _task("Turn on CAPE's web authentication")["community.general.ini_file"]
    assert (ini["section"], ini["option"], ini["value"]) == ("web_auth", "enabled", "yes")
    line = _task("Add the login middleware to CAPE's web settings")["ansible.builtin.lineinfile"]["line"]
    assert line == 'MIDDLEWARE = [*MIDDLEWARE, "web.lamware_login.LamwareLoginRequired"]'
    assert _task("Install the site-wide login middleware")["ansible.builtin.copy"]["dest"].endswith(
        "/web/web/lamware_login.py")


def test_the_password_is_root_only_and_never_logged():
    d = _task("Create the directory for the CAPE web login's password (root only)")["ansible.builtin.file"]
    assert (d["owner"], d["mode"]) == ("root", "0700")
    gen = _task("Generate the CAPE web login's password once")["ansible.builtin.shell"]
    assert "umask 077" in gen["cmd"] and gen["creates"] == "{{ cape_web_admin_password_file }}"
    for name in ("Read the CAPE web login's password", "Create or update the CAPE web login"):
        assert _task(name).get("no_log") is True, name
    user = _task("Create or update the CAPE web login")
    assert "LAMWARE_CAPE_WEB_PW" in user["environment"]
    assert "{{ cape_web_admin_pw" not in user["ansible.builtin.shell"]["cmd"], "password in argv"


def test_the_role_runs_it_after_the_superuser_exists():
    main = yaml.safe_load((ROLE / "tasks/main.yml").read_text())
    names = [t.get("name") for t in main]
    assert names.index("Create Django superuser for Cape API") < names.index("Require a login for CAPE's web UI")


# --- check 25, run for real -----------------------------------------------------------

CHECK25 = SMOKE[SMOKE.index('echo "[25/25]'):SMOKE.index("# Summary + ntfy alert on failure")]


def _check25(tmp_path, responses: dict[str, str]) -> str:
    bindir = tmp_path / "bin"
    bindir.mkdir()
    table = "\n".join(f'  "{p}") echo -n "{r}" ;;' for p, r in responses.items())
    (bindir / "curl").write_text('#!/bin/bash\nurl="${@: -1}"; p="${url#http://cape}"\n'
                                 f'case "$p" in\n{table}\n  *) echo -n "200 " ;;\nesac\n')
    (bindir / "runuser").write_text('#!/bin/bash\nwhile [ "$1" != "--" ]; do shift; done; shift; exec "$@"\n')
    (bindir / "psql").write_text("#!/bin/bash\necho 1321\n")
    for f in bindir.iterdir():
        f.chmod(0o755)
    body = CHECK25.replace("{{ cape_web_url | default('http://10.200.0.1:8000') }}", "http://cape").replace(
        "{{ cape_db_name | default('cape') }}", "cape")
    script = 'pass() { echo "PASS: $1"; }\nfail() { echo "FAIL: $1"; }\n' + body
    return subprocess.run(["bash", "-c", script], capture_output=True, text=True, timeout=30,
                          env={"PATH": f"{bindir}:/usr/bin:/bin"}).stdout


LOGIN = "302 http://cape/accounts/login/?next=/"
PAGES = ["/", "/analysis/", "/submit/", "/analysis/1321/", "/accounts/api-keys/", "/apiv2/", "/admin/", "/dashboard/"]


def test_check25_passes_when_every_page_redirects(tmp_path):
    r = {p: LOGIN for p in PAGES} | {"/accounts/login/": "200 ", "/apiv2/tasks/view/1321/": "401 "}
    assert "PASS: CAPE web UI" in _check25(tmp_path, r)


def test_check25_names_an_open_page(tmp_path):
    r = {p: LOGIN for p in PAGES} | {"/accounts/login/": "200 ", "/apiv2/tasks/view/1321/": "401 ",
                                    "/submit/": "200 "}
    out = _check25(tmp_path, r)
    assert "FAIL: CAPE web pages answer without a login: /submit/:[200]" in out, out


def test_check25_is_blind_when_the_login_page_is_down(tmp_path):
    r = {p: "502 " for p in PAGES + ["/accounts/login/"]}
    assert "FAIL: CAPE web-login probe is blind" in _check25(tmp_path, r)


def test_check25_fails_an_open_api(tmp_path):
    r = {p: LOGIN for p in PAGES} | {"/accounts/login/": "200 ", "/apiv2/tasks/view/1321/": "200 "}
    assert "API answered an unauthenticated request with 200" in _check25(tmp_path, r)


def test_check25_counts_a_redirect_elsewhere_as_open(tmp_path):
    """A 302 to another page (a dashboard that redirects to /analysis/) is still served
    without a login; only a redirect to the login page counts as protected."""
    r = {p: LOGIN for p in PAGES} | {"/accounts/login/": "200 ", "/apiv2/tasks/view/1321/": "401 ",
                                    "/": "302 http://cape/analysis/"}
    out = _check25(tmp_path, r)
    assert "FAIL: CAPE web pages answer without a login: /:[302 http://cape/analysis/]" in out, out
