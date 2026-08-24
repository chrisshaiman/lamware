# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
r"""Python's `$` also matches immediately before a trailing newline.

    >>> re.match(r"^[0-9]+$", "123\n")     # matches
    >>> re.fullmatch(r"^[0-9]+$", "123\n") # does not

So a validator written as `re.match(r"^...$", value)` accepts `value + "\n"` —
every one of them, without exception. It is not a quirk of any particular
pattern; it is what `$` means.

Found while fixing #438: `is_safe_task_id` shipped with `^[A-Za-z0-9]...$` and
accepted `"1022\n"` into a path join that unlinks what it finds. A sweep of the
tree then turned up sixteen more, of which the one that mattered was
`_TECHNIQUE_ID_RE` in the investigation system prompt — it is the bypass gate
for `_sanitize_untrusted`, so `"T1055\n"` skipped the CR/LF collapsing and put a
raw line break inside the UNTRUSTED_DATA fence.

Two guards here, because the class has two shapes:

  * a repo-wide structural check that no `re.*` CALL uses a `$`-anchored pattern
    where whole-string matching is meant, and
  * a behavioural check on the Ghidra argument table, whose patterns are bare
    data and are therefore invisible to the structural check.

The structural check deliberately ignores string literals that are not passed to
`re` — `GHIDRA_ARG_VALIDATORS` holds `^...$` patterns on purpose, and they are
safe because their consumer uses `re.fullmatch`. That is the fix that cannot be
forgotten when a pattern is added, which is why it was done at the consumer.
"""
import ast
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SKIP_DIRS = {".git", "node_modules", ".venv", "__pycache__", "dist", "build", ".mypy_cache"}

#: `re` functions whose first argument is a pattern.
_RE_FUNCS = {"match", "search", "fullmatch", "compile", "sub", "subn", "split",
             "findall", "finditer"}

#: Functions for which a trailing `$` is not a whole-string claim.
#: `search`/`findall`/`sub` and friends scan, and `fullmatch` already anchors.
_WHOLE_STRING_INTENT = {"match", "compile"}


def _python_files():
    for path in ROOT.rglob("*.py"):
        if not any(part in SKIP_DIRS for part in path.parts):
            yield path


def _ends_with_unescaped_dollar(pattern: str) -> bool:
    if not pattern.endswith("$"):
        return False
    backslashes = len(pattern) - len(pattern[:-1].rstrip("\\")) - 1
    return backslashes % 2 == 0


def _offenders() -> list[str]:
    out = []
    for path in _python_files():
        try:
            text = path.read_text(encoding="utf-8")
            tree = ast.parse(text)
        except (OSError, SyntaxError):
            continue
        lines = text.splitlines()
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            fn = node.func
            if not isinstance(fn, ast.Attribute) or fn.attr not in _RE_FUNCS:
                continue
            if getattr(fn.value, "id", None) not in ("re", "_re"):
                continue
            if fn.attr not in _WHOLE_STRING_INTENT:
                continue
            if not node.args or not isinstance(node.args[0], ast.Constant):
                continue
            pattern = node.args[0].value
            if not isinstance(pattern, str) or not _ends_with_unescaped_dollar(pattern):
                continue
            # Flags are POSITIONAL and their index differs per function:
            # re.compile(pat, flags) puts them at args[1], re.match(pat, s, flags)
            # at args[2]. Reading only one index is how the first version of this
            # sweep reported a MULTILINE pattern as an offender.
            flags = "".join(ast.dump(a) for a in node.args[1:])
            flags += "".join(ast.dump(k.value) for k in node.keywords if k.arg == "flags")
            if "MULTILINE" in flags or "'M'" in flags:
                continue
            # Per-line opt-out, requiring a reason. A file-level exclusion would
            # have been simpler and is exactly the hole this test exists to close:
            # the only file needing an exemption today is this one, whose job is
            # to DEMONSTRATE the bad form.
            source_line = lines[node.lineno - 1] if node.lineno <= len(lines) else ""
            if "anchor-ok:" in source_line:
                continue
            out.append(f"{path.relative_to(ROOT)}:{node.lineno}  re.{fn.attr}({pattern!r})")
    return sorted(out)


def test_the_property_this_test_exists_for():
    """Pinned first, so a Python version that changed `$` would fail HERE with a
    clear message rather than making every assertion below vacuous."""
    assert re.match(r"^[0-9]+$", "123\n"), "`$` no longer matches"  # anchor-ok: demonstrates the bug
    assert not re.fullmatch(r"^[0-9]+$", "123\n")
    assert not re.match(r"\A[0-9]+\Z", "123\n")


def test_no_whole_string_validator_is_anchored_with_a_bare_dollar():
    """Use `\\Z`, or call `re.fullmatch`. `$` lets a trailing newline through."""
    offenders = _offenders()
    assert not offenders, (
        "these patterns accept a trailing newline they were written to reject:\n  "
        + "\n  ".join(offenders))


def test_the_sweep_can_actually_see_an_offender(tmp_path, monkeypatch):
    """The check above passes on an empty file list too. Prove it finds one."""
    global ROOT
    original = ROOT
    try:
        (tmp_path / "bad.py").write_text(
            'import re\nP = re.compile(r"^[0-9]+$")\n', encoding="utf-8")
        ROOT = tmp_path
        assert any("bad.py" in o for o in _offenders())
    finally:
        ROOT = original


def test_the_pragma_requires_being_on_the_offending_line(tmp_path):
    """`anchor-ok:` is an opt-out, so it must not be possible to earn it by
    mentioning the string anywhere in the file."""
    global ROOT
    original = ROOT
    try:
        (tmp_path / "sneaky.py").write_text(
            'import re\n'
            '# anchor-ok: this comment is nowhere near the call\n'
            'P = re.compile(r"^[0-9]+$")\n', encoding="utf-8")
        ROOT = tmp_path
        assert any("sneaky.py" in o for o in _offenders()), (
            "a comment elsewhere in the file suppressed the finding")

        (tmp_path / "sneaky.py").write_text(
            'import re\n'
            'P = re.compile(r"^[0-9]+$")  # anchor-ok: deliberate\n', encoding="utf-8")
        assert _offenders() == [], "the pragma does not work on its own line"
    finally:
        ROOT = original


def test_the_sweep_does_not_flag_the_safe_forms(tmp_path):
    """MULTILINE, `\\Z`, `fullmatch` and `search` are all legitimate."""
    global ROOT
    original = ROOT
    try:
        (tmp_path / "ok.py").write_text(
            'import re\n'
            'A = re.compile(r"^## (x)$", re.M)\n'
            'B = re.compile(r"\\A[0-9]+\\Z")\n'
            'C = re.fullmatch(r"^[0-9]+$", "1")\n'
            'D = re.search(r"foo$", "x")\n',
            encoding="utf-8")
        ROOT = tmp_path
        assert _offenders() == []
    finally:
        ROOT = original


# --- the Ghidra argument table, which the structural check cannot see -------

@pytest.mark.parametrize("tool,arg,value", [
    ("decompile_function", "name", "DecryptConfig"),
    ("get_xrefs_to", "name", "DecryptConfig"),
    ("get_xrefs_from", "name", "DecryptConfig"),
    ("get_strings_at", "address", "0x00401000"),
    ("get_strings_at", "range", "4096"),
    ("list_functions", "filter", "Decrypt*"),
    ("get_data_at", "address", "0x00401000"),
    ("get_data_at", "length", "512"),
])
def test_no_ghidra_arg_accepts_a_trailing_newline(tool, arg, value):
    """These patterns keep their `^...$` anchors; the fix is that their consumer
    uses `re.fullmatch`. Asserted through the real validator, so it holds however
    the table is written."""
    from lamware_shared.tool_validators import validate_ghidra_args

    assert validate_ghidra_args(tool, {arg: value}) is None, (
        "precondition: this value must be accepted, or the test below proves nothing")
    assert validate_ghidra_args(tool, {arg: value + "\n"}) is not None, (
        f"{tool}.{arg} accepts {value + chr(10)!r}")


def test_every_pattern_in_the_table_is_covered_above():
    """A pattern added to the table without a case here would be untested, and
    the parametrize list is the kind of thing that quietly falls behind."""
    from lamware_shared.tool_validators import GHIDRA_ARG_VALIDATORS

    declared = {(tool, arg) for tool, args in GHIDRA_ARG_VALIDATORS.items() for arg in args}
    covered = {
        ("decompile_function", "name"), ("get_xrefs_to", "name"),
        ("get_xrefs_from", "name"), ("get_strings_at", "address"),
        ("get_strings_at", "range"), ("list_functions", "filter"),
        ("get_data_at", "address"), ("get_data_at", "length"),
    }
    assert declared == covered, f"uncovered: {sorted(declared - covered)}"
