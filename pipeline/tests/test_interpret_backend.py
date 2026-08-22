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


def test_backend_flag_is_a_flag_not_a_client():
    """It used to select a CLIENT: `ss_client = summary_client if ... else client`.

    That shape was the bug. summary_client speaks to /v1/messages, where a local
    model's thinking cannot be disabled, so every stage that "selected local" got an
    empty response. Measured 2026-08-20 at max_tokens=1024: dotnet, go_goresym and
    powershell each returned 0 characters after burning the full budget, and visual
    returned 0 after 302s. The flag was wired, guarded, and non-functional.

    It is now a boolean consumed by single_shot_completion, which picks the transport
    that can actually answer.
    """
    text = SCRIPT.read_text(encoding="utf-8")
    assert 'ss_local = config.get("single_shot_backend") == "local"' in text
    assert "ss_client = summary_client" not in text, (
        "selecting a client here reintroduces the empty-response bug")


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
        # Two shapes now: converted stages call single_shot_completion(ss_local, ...);
        # unconverted ones still call client.messages.create directly.
        if "single_shot_completion(" in ln and stage:
            out.setdefault(stage, "single_shot_completion")
        c = re.search(r"response = (client)\.messages\.create", ln)
        if c and stage:
            out.setdefault(stage, c.group(1))
    return out


def test_the_stage_parser_finds_every_known_path():
    """Without this the two tests below pass vacuously if the dispatch is refactored."""
    found = set(_client_by_stage())
    missing = (_WIRED | _NOT_WIRED) - found
    assert not missing, f"parser located no client call for {sorted(missing)}"


def test_wired_paths_go_through_single_shot_completion():
    """Honouring the flag means routing through the dispatcher, not picking a client.

    A stage that reads ss_local and then calls the anthropic client anyway is the
    original defect with extra steps.
    """
    found = _client_by_stage()
    wrong = {s: found.get(s) for s in sorted(_WIRED)
             if found.get(s) != "single_shot_completion"}
    assert not wrong, f"these must dispatch via single_shot_completion: {wrong}"


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


def _dispatcher_body() -> str:
    """single_shot_completion's source, comments and docstring stripped.

    An absence check must not be satisfiable by the prose explaining the absence —
    the docstring here quotes the very transport it must not use.
    """
    import re
    src = SCRIPT.read_text(encoding="utf-8")
    body = re.search(r"^def single_shot_completion\(.*?(?=^def |\Z)", src, re.S | re.M)
    assert body, "single_shot_completion not found"
    out, in_doc = [], False
    for ln in body.group(0).splitlines():
        s = ln.strip()
        if s.startswith('"""') or s.endswith('"""'):
            if s.count('"""') == 1:
                in_doc = not in_doc
            continue
        if in_doc or s.startswith("#"):
            continue
        out.append(ln)
    return "\n".join(out)


def test_the_local_branch_actually_routes_somewhere():
    """The call-site guards above pass even if the local branch never fires.

    Verified: replacing the branch condition with `if False:` — which restores the
    exact bug, every local stage falling through to the anthropic client — left all
    of them green. Shape assertions cannot see behaviour, so this pins the branch.
    """
    body = _dispatcher_body()
    assert "if use_local" in body, (
        "the local branch must be reachable; a disabled condition silently restores "
        "the empty-response bug")
    local_half = body.split("if use_local", 1)[1].split("response = anthropic_client")[0]
    assert "/chat/completions" in local_half, (
        "local must post to the OpenAI leg — /v1/messages returns 0 characters")
    assert "enable_thinking" in local_half, (
        "local must disable thinking, or the whole budget goes to reasoning")


def test_the_cloud_branch_still_uses_the_anthropic_client():
    body = _dispatcher_body()
    assert "anthropic_client.messages.create" in body, (
        "cloud models must keep the passthrough — prompt caching lives there")


def test_images_survive_the_conversion():
    """A multimodal stage over the OpenAI leg loses its images silently without this:
    the request succeeds and the model describes nothing."""
    src = SCRIPT.read_text(encoding="utf-8")
    assert "image_url" in src and "_to_openai_content" in src, (
        "Anthropic image blocks must be converted to OpenAI image_url parts")
