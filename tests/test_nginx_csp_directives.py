# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""The app's Content-Security-Policy carries the directives it is meant to (#731).

test_nginx_security_headers asserts the header is present; this asserts what it
says. Parses every app CSP in the rendered nginx template into directives and
checks their values, so a dropped or loosened directive fails here. Structural:
the browser behaviour each directive produces needs a browser to observe.
"""
import re
from pathlib import Path

TEMPLATE = (Path(__file__).resolve().parents[1]
            / "ansible/roles/frontend/templates/lamware-nginx.conf.j2")

REQUIRED = {
    "default-src": {"'self'"},
    "script-src": {"'self'"},
    "img-src": {"'self'", "data:"},
    "frame-ancestors": {"'none'"},
    "base-uri": {"'self'"},
    "form-action": {"'self'"},
}


def _app_csps() -> list[dict[str, set[str]]]:
    # The raw template: the CSP lines hold only {{ frontend_server_name }}, and
    # rendering the whole file needs Ansible's filters.
    text = TEMPLATE.read_text()
    out = []
    for value in re.findall(r'add_header\s+Content-Security-Policy\s+"([^"]+)"', text):
        d = {}
        for part in value.split(";"):
            words = part.split()
            if words:
                d[words[0]] = set(words[1:])
        if "connect-src" in d:   # the app's CSP; the Keycloak admin location has its own
            out.append(d)
    return out


def test_the_app_csps_were_found():
    assert len(_app_csps()) >= 2


def test_every_app_csp_has_the_required_directive_values():
    for csp in _app_csps():
        for name, values in REQUIRED.items():
            assert csp.get(name) == values, f"{name}: {csp.get(name)}"
