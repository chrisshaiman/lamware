# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""Redaction helpers for the smoke gate.

Split out of conftest.py so the guards in tests/test_smoke_config_never_prints_secrets.py
can import them WITHOUT importing playwright. Left in conftest, the guard skipped
everywhere playwright is absent — including CI — which is no guard at all.
"""
import re

# Console text is untrusted and may carry a bearer token from a failed XHR.
# Anything long and token-shaped is replaced before it can reach a log.
# Three base64url runs separated by dots is the JWT shape, and it is distinctive
# enough on its own — the length floor is deliberately low because a real header
# segment can be short (`eyJhbGciOiJIUzI1NiJ9` is 20 chars, which a 24-char floor
# let straight through).
_TOKENISH = re.compile(r"[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}"
                       r"|(?i:bearer)\s+[A-Za-z0-9._\-]{16,}")


def redact(text: str) -> str:
    """Strip token-shaped runs from console output, keeping it short enough to read."""
    return _TOKENISH.sub("<redacted-token>", text or "")[:400]


class SmokeConfig(dict):
    """Config that cannot print the smoke user's password.

    `config` is a FIXTURE ARGUMENT of every smoke test, and pytest prints each
    argument in the failure header:

        page = <Page ...>, config = {'password': '...', 'user': 'smoke-test'}

    So any failing smoke test published a live credential into the deploy log,
    CI output, and anywhere that output was pasted. A dict subclass is used
    rather than dropping the key because fixtures already index it; this redacts
    every path that renders it (`repr`, `str`, `--showlocals`) without changing
    how it is read.
    """

    _SECRET_KEYS = ("password", "token", "secret")

    def __repr__(self) -> str:
        shown = {k: ("<redacted>" if any(x in k.lower() for x in self._SECRET_KEYS) else v)
                 for k, v in self.items()}
        return f"SmokeConfig({shown!r})"

    # No __str__ override: dict does not define one, so object.__str__ routes
    # str() and f-strings through __repr__ above. An explicit alias here was
    # redundant — no mutation could kill it, which is how it was spotted.
