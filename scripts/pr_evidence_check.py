#!/usr/bin/env python3
# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""Refuse to merge a PR that has not been deployed from its own branch.

Through #635 the pattern was: merge within minutes, deploy from main, watch the
deploy fail, open the next PR. The one test that could see the failure ran
after the irreversible step. This check moves it in front.

The PR body must carry the line `make merge-check` prints:

    Provenance commit: <sha>

and that sha must be the PR's head. A push invalidates the evidence by
construction, because the head moves and the line does not.

Docs-only PRs are exempt. Nothing else is: a Makefile or CI change still has to
go through the gate it changes.

The logic is a pure function so it can be tested without GitHub. The workflow
passes the body through an environment variable, never interpolated into a
shell line, because the body is written by whoever opened the PR.
"""
from __future__ import annotations

import argparse
import os
import re
import sys
from pathlib import Path

# A PR is docs-only when every changed path matches one of these. Deliberately
# narrow: .github/workflows, tests/, Makefile and VERSION change what runs or
# what is built, so they are not documentation whatever their extension.
DOCS_ONLY = (
    re.compile(r"\.md\Z", re.IGNORECASE),
    re.compile(r"^docs/"),
    re.compile(r"\AAUTHORS\Z"),
    re.compile(r"^LICENSE"),
    re.compile(r"\A\.github/CODEOWNERS\Z"),
    re.compile(r"^\.github/ISSUE_TEMPLATE/"),
)

# The line `make merge-check` prints. 12 hex chars is the shortest form the
# Makefile ever shows; anything shorter is a typo, not evidence.
PROVENANCE_LINE = re.compile(r"provenance commit:\s*`?([0-9a-fA-F]{12,40})`?", re.IGNORECASE)

# The template placeholder, so an unedited template cannot pass by accident.
PLACEHOLDER = re.compile(r"provenance commit:\s*<", re.IGNORECASE)

HOW_TO_FIX = (
    "  git checkout <this branch>\n"
    "  make deploy TAGS=<roles this PR touches>\n"
    "  make merge-check\n"
    "then paste its output, including the 'Provenance commit:' line, under\n"
    "'Host evidence' in the PR body. Every push moves the head, so redeploy and\n"
    "re-run after each one."
)


def is_docs_only(changed_files: list[str]) -> bool:
    """True when every changed path is documentation. An empty list is not docs-only:
    it means the diff could not be computed, and a check that passes on missing
    input is the shape of bug this repo keeps finding (#336, #577)."""
    if not changed_files:
        return False
    return all(any(p.search(f) for p in DOCS_ONLY) for f in changed_files)


def evaluate(body: str | None, head_sha: str, changed_files: list[str]) -> tuple[bool, str]:
    """Decide whether the PR carries deploy evidence for its current head.

    Returns (ok, message). The message is printed either way so the CI log says
    *why*, not just red or green.
    """
    body = body or ""
    head = head_sha.strip().lower()

    if is_docs_only(changed_files):
        return True, (f"docs-only change ({len(changed_files)} file(s)); "
                      "no deploy evidence required.")

    if PLACEHOLDER.search(body):
        return False, ("'Provenance commit:' still holds the template placeholder.\n"
                       "This PR changes deployed or build-affecting files, so it must be\n"
                       "deployed from its branch before merge:\n" + HOW_TO_FIX)

    match = PROVENANCE_LINE.search(body)
    if not match:
        return False, ("no 'Provenance commit: <sha>' line in the PR body.\n"
                       "This PR changes deployed or build-affecting files, so it must be\n"
                       "deployed from its branch before merge:\n" + HOW_TO_FIX)

    cited = match.group(1).lower()
    if head.startswith(cited):
        return True, f"deploy evidence cites {cited[:12]}, which is the PR head."

    return False, (f"deploy evidence cites {cited[:12]} but the PR head is {head[:12]}.\n"
                   "The branch moved after the deploy that produced this evidence, so\n"
                   "the host is not running what would be merged. Redeploy and re-run:\n"
                   + HOW_TO_FIX)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--head-sha", required=True, help="the PR head commit")
    parser.add_argument("--changed-files", required=True, type=Path,
                        help="file with one changed path per line")
    parser.add_argument("--body-env", default="PR_BODY",
                        help="environment variable holding the PR body")
    args = parser.parse_args(argv)

    changed = [ln.strip() for ln in args.changed_files.read_text(encoding="utf-8").splitlines()
               if ln.strip()]
    ok, message = evaluate(os.environ.get(args.body_env), args.head_sha, changed)
    print(("OK: " if ok else "FAIL: ") + message)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
