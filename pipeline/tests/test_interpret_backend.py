# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""Static guard: which stages honour single_shot_backend, and which deliberately do not."""
from pathlib import Path

SCRIPT = (Path(__file__).resolve().parents[2]
          / "ansible" / "roles" / "interpret" / "files" / "interpret-ghidra.py")


def _comment_block_above(anchor: str) -> str:
    """The contiguous comment lines immediately preceding `anchor`.

    Walks backwards over `#` lines rather than slicing a fixed character window. The
    window version is a known trap in this repo: test_interpret_synthesis.py records
    that fixed windows "silently truncate the moment anyone adds a comment above the
    code being asserted on -- which is exactly how adding the #246 comment broke two
    passing tests without changing a line of their subject". A comment guard built on
    one would fail on unrelated edits above it, which is how a guard earns removal.
    """
    lines = SCRIPT.read_text(encoding="utf-8").splitlines()
    idx = next(i for i, ln in enumerate(lines) if anchor in ln)
    out = []
    for line in reversed(lines[:idx]):
        if line.strip().startswith("#"):
            out.append(line)
        elif line.strip() == "":
            continue
        else:
            break
    return "\n".join(reversed(out))


def test_ss_client_defined_from_backend_flag():
    text = SCRIPT.read_text(encoding="utf-8")
    assert 'ss_client = summary_client if config.get("single_shot_backend") == "local" else client' in text


#: Stages wired to the single-shot backend knob, and the stages deliberately not.
#: Named rather than counted: the previous version asserted `== 3` with no record of
#: WHICH three or why, so a change could satisfy it by moving one stage in and another
#: out. It also could not say whether a fourth was an oversight or a decision.
_WIRED = {"dotnet", "go_goresym", "powershell", "visual_analysis"}
_NOT_WIRED = {"java_cfr", "office_macro", "pyinstaller", "evasion_hunter"}


def _client_by_stage() -> dict[str, str]:
    import re
    stage, out = None, {}
    for ln in SCRIPT.read_text(encoding="utf-8").splitlines():
        m = re.search(r'analysis_type"\)\s*==\s*"([a-z_0-9]+)"', ln)
        if m:
            stage = m.group(1)
        c = re.search(r"response = (ss_client|client)\.messages\.create", ln)
        if c and stage:
            out.setdefault(stage, c.group(1))
    return out


def test_the_stage_parser_finds_every_known_path():
    """Without this the two tests below pass vacuously if the dispatch is refactored."""
    found = set(_client_by_stage())
    missing = (_WIRED | _NOT_WIRED) - found
    assert not missing, f"parser located no client call for {sorted(missing)}"


def test_wired_paths_use_ss_client():
    found = _client_by_stage()
    wrong = {s: found[s] for s in sorted(_WIRED) if found.get(s) != "ss_client"}
    assert not wrong, f"these must honour single_shot_backend: {wrong}"


def test_unwired_paths_stay_on_the_cloud_client():
    """The pilot boundary is a decision, not an accident.

    visual_analysis was added to _WIRED on 2026-08-20 on measured grounds: it runs on
    12 of 13 recorded analyses (screenshots come from CAPE detonation, so every
    sample), and it is the only stage that transmits base64 screenshots of detonated
    malware — ransom notes, credential dialogs, C2 panels — which every report on
    record sent to claude-sonnet-4-6 via the anthropic passthrough.

    The remaining four are file-type gated and fired on 0 of those same 13. Moving
    them would swap Sonnet for a 35B on paths that rarely run, with no measurement of
    the quality cost. Widen this set only with a reason recorded here.
    """
    found = _client_by_stage()
    moved = {s: found[s] for s in sorted(_NOT_WIRED) if found.get(s) != "client"}
    assert not moved, (
        f"{moved} moved onto the local backend without widening _NOT_WIRED — if that "
        f"is intended, record why here")


def test_local_re_swaps_to_the_router_client():
    """Load-bearing, not an optimisation (#273).

    The /anthropic passthrough serves NO local model — measured over the production
    UDS on 2026-08-02, `local-qwen-llamacpp-re` returns 404 there and 200 on the
    router. So deleting this branch does not make local RE slower or less
    cache-friendly; it makes local RE impossible.

    It reads like a tunable, which is exactly why it needs a guard: the comment used
    to call it an "A/B knob", and nothing else in the file says the passthrough cannot
    serve the model it would fall back to.
    """
    text = SCRIPT.read_text(encoding="utf-8")
    assert 'if config.get("re_backend") == "local" and router_base:' in text, (
        "the local-RE branch is required — without it the loop keeps the /anthropic "
        "client, which 404s for every local model")
    branch = text.split('if config.get("re_backend") == "local" and router_base:', 1)[1][:300]
    assert "client = summary_client" in branch, (
        "the branch must swap to the ROUTER client (summary_client); the passthrough "
        "cannot reach a local model at all")


def test_the_transport_comment_names_both_routes():
    """An unqualified 'the RE path uses the passthrough' reads as universal.

    It is true for cloud RE and false for local RE, and that ambiguity cost four 404s
    setting up #260 — the cheap failure. The expensive one is silent: any prompt-cache
    reasoning about local qwen that cites the passthrough is about a transport local
    runs never touch, and #246's investigation was exactly that.
    """
    block = _comment_block_above("router_base = os.environ.get")
    assert "404" in block, (
        "the transport comment should carry the measured evidence, not an assertion")
    upper = block.upper()
    assert "CLOUD" in upper and "ROUTER" in upper, (
        "it must say which transport serves which path, rather than naming one")
