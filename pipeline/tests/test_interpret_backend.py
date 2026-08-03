# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""Static guard: the single-shot backend knob is wired to exactly the 3 pilot paths."""
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


def test_exactly_three_pilot_paths_use_ss_client():
    text = SCRIPT.read_text(encoding="utf-8")
    # .NET, Go, PowerShell — and only those — route through ss_client.
    assert text.count("ss_client.messages.create(") == 3


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
