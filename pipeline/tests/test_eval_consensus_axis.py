# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""Consensus must refuse to run without an independent axis (#292).

`--consensus-k` used to default to 2 and auto-render for any seeded arm. Both
halves were wrong at once:

  - the seeds are inert. llama-server honours `seed` on /v1/chat/completions but
    ignores it on /v1/messages, and #285 moved the RE transport to /v1/messages
    because the OpenAI leg discarded thinking and returned `content: []` on
    tool-calling turns (#283). Three seeds produced byte-identical 28 KB
    transcripts.
  - so every claim appeared in every run, consensus reported 100% agreement, and
    k=2 did exactly what `__main__` rejects k=1 for — while looking rigorous.

The scorecard's most authoritative-looking section was the one asserting nothing.

These tests pin the refusal at BOTH levels, because they fail differently:

  argv level   — refuses before the sweep. Learning this after the fact costs
                 hours of local inference for a section that cannot be used.
  render level — refuses on the data itself, so it stays correct if independence
                 is ever restored (#310) without anyone remembering to update it.
"""
import ast
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "ansible" / "roles" / "pipeline" / "files"))

from lamware_eval.__main__ import build_parser, consensus_axis_error, main  # noqa: E402
from lamware_eval.arms import parse_arms  # noqa: E402

MAIN_PY = (ROOT / "ansible" / "roles" / "pipeline" / "files" / "lamware_eval"
           / "__main__.py")


def _code_only(path: Path) -> str:
    """Source with comments and docstrings stripped, still readable as source.

    Absence assertions must not be satisfiable by the prose that explains the
    absence. This file's own module docstring names the strings under test, and
    `__main__.py`'s comments quote the removed trigger verbatim — a plain
    substring check over raw text would find those and pass while the code was
    still wrong.

    Round-tripping through `ast` rather than filtering tokens is deliberate.
    A token filter has to re-join the stream, and any separator that is not the
    original layout breaks multi-token substrings: joining on "\\n" turns
    `a.seed is not None` into six lines, and every `assert "..." not in code`
    then passes unconditionally. That version of this helper shipped, looked
    thorough, and detected nothing — a mutation test caught it. `ast.unparse`
    emits normalized but contiguous source, and comments never survive parsing
    at all.
    """
    tree = ast.parse(path.read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if not isinstance(node, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef,
                                 ast.ClassDef)):
            continue
        body = node.body
        if (body and isinstance(body[0], ast.Expr)
                and isinstance(body[0].value, ast.Constant)
                and isinstance(body[0].value.value, str)):
            node.body = body[1:] or [ast.Pass()]
    return ast.unparse(ast.fix_missing_locations(tree))


def _run_cli(argv: list[str]) -> pytest.ExceptionInfo:
    sys.argv = ["lamware_eval", *argv]
    with pytest.raises(SystemExit) as exc:
        main()
    return exc


# ---------------------------------------------------------------------------
# The axis check itself
# ---------------------------------------------------------------------------

def test_seed_variants_of_one_arm_are_refused():
    """THE regression. This is the exact invocation that produced vacuous 100%
    agreement for weeks: same arm, different seed names."""
    err = consensus_axis_error(parse_arms("qwen@10:s42,qwen@10:s1337"))
    assert err is not None, "seed variants of one arm must not be reconcilable"
    assert "#292" in err, "the refusal must point at the evidence, not just refuse"


def test_three_seeds_are_refused_too():
    """k=3 across three seeds looks more rigorous and is equally vacuous."""
    err = consensus_axis_error(parse_arms("qwen@10:s42,qwen@10:s1337,qwen@10:s8675309"))
    assert err is not None


def test_depth_arms_are_refused_because_one_is_a_prefix_of_the_other():
    """The subtle one. Depth LOOKS like an independence axis.

    Under determinism qwen@10's trajectory is a literal prefix of qwen@15's on
    the same sample, so agreement on anything in the first 10 calls is guaranteed
    by construction. Reconciling across depth would be #292 wearing a new hat.
    """
    err = consensus_axis_error(parse_arms("qwen@10,qwen@15"))
    assert err is not None
    assert "PREFIX" in err or "prefix" in err, (
        "the message must explain WHY depth is not an axis, or someone will "
        "reasonably assume it was an oversight and re-enable it")


def test_a_single_arm_is_refused():
    err = consensus_axis_error(parse_arms("qwen@10"))
    assert err is not None


def test_cross_model_is_refused_as_unimplemented_not_as_invalid():
    """Distinct models ARE the valid axis (#310) — but the grouping still keys on
    seed, so it would reconcile nothing and print an empty section.

    Refusing beats a silent no-op. The message must distinguish 'not yet' from
    'never', or #310 looks closed.
    """
    err = consensus_axis_error(parse_arms("qwen@10,claude-sonnet-5"))
    assert err is not None
    assert "#310" in err
    assert "not implemented" in err.lower()


# ---------------------------------------------------------------------------
# CLI wiring — the refusal must land before the sweep, not after
# ---------------------------------------------------------------------------

def test_cli_rejects_seeded_consensus_before_reading_the_config():
    """--config and --corpus point at paths that do not exist.

    If the CLI reaches them it raises FileNotFoundError instead of exiting
    cleanly, which is how this test detects the check drifting below the I/O.
    A sweep that fails after four hours has already spent the four hours.
    """
    exc = _run_cli(["run", "--corpus", "/nonexistent/corpus.json",
                    "--config", "/nonexistent/config.json",
                    "--arms", "qwen@10:s42,qwen@10:s1337", "--consensus-k", "2"])
    assert exc.value.code == 2, "argparse usage error expected, not a crash"


def test_cli_still_rejects_k_of_one():
    exc = _run_cli(["run", "--corpus", "/nonexistent/corpus.json",
                    "--arms", "qwen@10", "--consensus-k", "1"])
    assert exc.value.code == 2


def test_cli_rejects_negative_k():
    exc = _run_cli(["run", "--corpus", "/nonexistent/corpus.json",
                    "--arms", "qwen@10", "--consensus-k", "-1"])
    assert exc.value.code == 2


def test_consensus_is_off_by_default():
    """The default was 2. A sweep nobody asked a consensus question of printed a
    consensus section anyway, and that section was the vacuous one.

    Asserted against argparse's resolved default rather than the source text, so
    it tests behaviour instead of spelling.
    """
    assert build_parser().get_default("consensus_k") == 0, (
        "--consensus-k must default to 0 (disabled); any other default reinstates "
        "the section that reported 100% agreement over identical runs")


def test_the_seed_auto_trigger_is_gone():
    """Consensus must render only on explicit request.

    Checked against comment-stripped source: `__main__.py` quotes the removed
    trigger in a comment explaining why it was removed, and this file's docstring
    does too. A substring check over raw text passes on that prose alone.
    """
    code = _code_only(MAIN_PY)
    assert "a.seed is not None" not in code, (
        "the `any(a.seed is not None)` auto-trigger must not gate rendering — "
        "that is what silently added the vacuous section")
    assert "consensus_k" in code


def test_the_absence_check_can_actually_fail(tmp_path):
    """Guards the guard — and the POSITIVE control is the load-bearing half.

    The first version of `_code_only` joined tokens on "\\n", so the phrase under
    test was split across six lines and `not in` passed no matter what the source
    said. It satisfied the negative control (comments stripped) and the
    survives-real-code control (single tokens present) while detecting nothing.

    Only the positive control below distinguishes them: source that genuinely
    contains the trigger must still contain it, contiguously, after stripping.
    """
    probe = tmp_path / "probe.py"
    probe.write_text(
        '"""a.seed is not None in a docstring."""\n'
        "# a.seed is not None in a comment\n"
        "keep = 1  # trailing\n"
    )
    stripped = _code_only(probe)
    assert "a.seed is not None" not in stripped, "comments and docstrings must go"
    assert "keep = 1" in stripped, "real code must survive, with its layout intact"

    live = tmp_path / "live.py"
    live.write_text("md = 1 if any(a.seed is not None for a in arms) else 2\n")
    assert "a.seed is not None" in _code_only(live), (
        "POSITIVE CONTROL: a helper that mangles spacing makes every `not in` "
        "assertion in this file pass unconditionally")
