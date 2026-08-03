# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""Prove the smoke gate's browser can actually launch (#269).

`playwright install chromium` exits 0 when the host is missing the browser's shared
libraries — it prints a banner and carries on. So `make smoke-setup` used to announce
"Smoke gate ready" in a state where the browser could never start, and the `make smoke`
failure that followed read as "the deploy broke the site" rather than "this workstation
is missing three apt packages".

Downloading a browser is not the same as being able to run one, and only running one
proves it. This is the check that closes that gap.

Lives in a file rather than a `python -c` inside the Makefile because the first attempt
at this WAS a one-liner: `try:`/`except` cannot be joined with semicolons, so it was a
SyntaxError swallowed by `2>/dev/null`, and the diagnostic printed nothing at all. A
check that fails silently is the bug this issue is about.

Exit 0 = the gate can run here. Exit 1 = control-node problem, with guidance.
"""
import sys

VENV_HINT = "tests/smoke/.venv/bin/playwright"


def main() -> int:
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        print("ERROR: playwright is not installed in the smoke venv.", file=sys.stderr)
        print("       Run: make smoke-setup", file=sys.stderr)
        return 1

    try:
        with sync_playwright() as pw:
            pw.chromium.launch(headless=True).close()
    except Exception as exc:  # noqa: BLE001 - any launch failure is the same verdict
        print("", file=sys.stderr)
        print("ERROR: Chromium cannot launch — the smoke gate cannot run on this "
              "machine.", file=sys.stderr)
        print("       This is a CONTROL NODE problem, not a problem with the deployed "
              "site.", file=sys.stderr)
        print("", file=sys.stderr)
        print("       Usually the host is missing the browser's shared libraries:",
              file=sys.stderr)
        print("         sudo apt-get install -y libnss3 libnspr4 libasound2t64",
              file=sys.stderr)
        print("       or, to let playwright choose them:", file=sys.stderr)
        print(f"         sudo {VENV_HINT} install-deps", file=sys.stderr)
        print("", file=sys.stderr)
        print("       If the browser itself is missing, re-run:  make smoke-setup",
              file=sys.stderr)
        print("", file=sys.stderr)
        print("       What playwright reported:", file=sys.stderr)
        for line in str(exc).splitlines()[:14]:
            print(f"         {line}", file=sys.stderr)
        print("", file=sys.stderr)
        return 1

    print("==> Browser launches OK.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
