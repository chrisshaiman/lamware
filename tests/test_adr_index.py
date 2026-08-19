# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""The ADR index and its inbound links must stay in step with the ADRs (#418).

`docs/DECISIONS.md` is the most credible artifact in the repository — an adversarial
reviewer moved from "needs empirical validation" to "scientific honesty 9/10" on the
strength of ADR-019 alone. Its only entry point used to be one row in a table below the
Disclaimer, and ARCHITECTURE.md's section literally titled "Key technical decisions" did
not link to it at all. #418 made both into routers.

A hand-maintained index is a claim about a file that changes, which is the same shape as
the README claims guarded in #416: correct on the day it is written, silently wrong
afterwards. An ADR added without an index row is invisible; an index row pointing at a
renamed heading is a dead link a reader hits instead of the record.

Anchors are computed the way GitHub computes them rather than eyeballed, because the
headings carry em-dashes, slashes, plus signs and parentheses that all vanish differently.
"""
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DECISIONS = (ROOT / "docs" / "DECISIONS.md").read_text(encoding="utf-8")
ARCHITECTURE = (ROOT / "ARCHITECTURE.md").read_text(encoding="utf-8")

_HEADING = re.compile(r"^## (ADR-(\d+):.*)$", re.M)


def _slug(heading: str) -> str:
    """GitHub's heading -> anchor transform: lowercase, drop punctuation, spaces to hyphens.

    Punctuation is REMOVED rather than replaced, so "mode — GOVERNANCE" collapses to
    "mode--governance" (two hyphens from the spaces that flanked the em-dash) and
    "clean + office" to "clean--office". Getting this wrong produces links that look
    right and 404 to the top of the page.
    """
    s = heading.lower()
    s = re.sub(r"[^\w\s-]", "", s)      # \w keeps underscores, which GitHub also keeps
    return re.sub(r"\s", "-", s)


def _adrs() -> dict[str, str]:
    """{number: anchor} for every ADR heading in the log."""
    return {num: _slug(full) for full, num in _HEADING.findall(DECISIONS)}


def test_every_adr_appears_in_the_index():
    """An ADR with no index row is invisible to anyone who did not already know it."""
    adrs = _adrs()
    assert adrs, "no ADR headings parsed — fix the parser, do not delete the test"
    index = DECISIONS.split("## ADR-001")[0]
    missing = [n for n in adrs if f"#adr-{n}-" not in index]
    assert not missing, f"ADR(s) {sorted(missing)} are not linked from the index"


def test_index_links_resolve_to_real_headings():
    anchors = set(_adrs().values())
    index = DECISIONS.split("## ADR-001")[0]
    for link in re.findall(r"\(#(adr-[\w-]+)\)", index):
        assert link in anchors, f"index links #{link}, which matches no ADR heading"


def test_architecture_router_links_resolve():
    """ARCHITECTURE.md's decisions table is the bridge into the log; a dead link there
    sends a reader looking for reasoning to the top of a 830-line file instead."""
    anchors = set(_adrs().values())
    links = re.findall(r"docs/DECISIONS\.md#(adr-[\w-]+)", ARCHITECTURE)
    assert links, "ARCHITECTURE.md no longer routes into the ADR log"
    for link in links:
        assert link in anchors, f"ARCHITECTURE.md links #{link}, which matches no ADR"


def test_readme_evaluation_cites_adr_019_inline():
    """The negative result is the README's strongest claim, and ADR-019 is the record
    behind it. The citation belongs where the number is stated — a reader checking
    "0/14" should reach the reasoning in one click, not find it in a table at the end.
    """
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    evaluation = readme.split("## Evaluation", 1)
    assert len(evaluation) == 2, "README has no Evaluation section"
    section = evaluation[1].split("\n## ", 1)[0]
    assert "ADR-019" in section, (
        "README's Evaluation section states the family-attribution result without "
        "citing ADR-019, which is the record for it")


# --- statuses a reader can act on ------------------------------------------

def test_every_adr_declares_a_status():
    for full, num in _HEADING.findall(DECISIONS):
        body = DECISIONS.split(f"## {full}", 1)[1]
        head = body.split("**Context:**", 1)[0]
        assert "**Status:**" in head, f"ADR-{num} has no Status line"


def test_aws_era_adrs_are_not_presented_as_live():
    """ADR-016 removed the AWS data plane and #211 deleted the code. Four ADRs describe
    that plane and read as current decisions unless their status says otherwise — which
    is how a reader ends up implementing an SQS pipeline that does not exist.

    007 is deliberately NOT in this list: ADR-016 keeps S3 Object Lock as a standalone
    future option, so it is deferred rather than superseded, and the distinction is the
    point.
    """
    for num in ("003", "006", "008"):
        m = re.search(rf"^## ADR-{num}:.*?\n\n(\*\*Status:\*\*.*?)\n\n", DECISIONS, re.S | re.M)
        assert m, f"ADR-{num} status block not found"
        assert "Superseded" in m.group(1), (
            f"ADR-{num} describes the removed AWS data plane but its status does not say "
            f"it is superseded")
