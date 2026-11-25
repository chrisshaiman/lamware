# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""The plain-English call must leave room for thinking, and say so when it gets no text.

Measured 2026-11-25 on the host: with the haiku profile, eval-haiku55 spent all 200
max_tokens thinking (output_tokens 200, no text block), and the report carried an empty
plain_english_summary with no usage and no reason. Current models think by default,
and max_tokens bounds thinking and text together.

The fake server below behaves that way: below THINKING tokens of budget it returns only
a thinking block, above it a thinking block and the text. The container's own
plain-English branch runs against it, end to end through the anthropic SDK.
"""
from __future__ import annotations

import importlib.util
import io
import json
import stat
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
THINKING = 600          # what the fake model spends thinking before it writes anything


def _load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    try:
        spec.loader.exec_module(mod)
    finally:
        sys.modules.pop(name, None)
    return mod


class _Thinker(BaseHTTPRequestHandler):
    seen: list = []
    thinking = THINKING

    def log_message(self, *a):
        pass

    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        type(self).seen.append(body)
        budget = body["max_tokens"]
        content = [{"type": "thinking", "thinking": "", "signature": "sig"}]
        if budget > self.thinking:
            content.append({"type": "text", "text": "It steals your passwords."})
        out = json.dumps({
            "id": f"msg_{len(self.seen)}", "type": "message", "role": "assistant",
            "model": body["model"], "content": content,
            "stop_reason": "end_turn" if budget > self.thinking else "max_tokens",
            "stop_sequence": None,
            "usage": {"input_tokens": 100, "output_tokens": min(budget, self.thinking + 20)},
        }).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(out)))
        self.end_headers()
        self.wfile.write(out)


@pytest.fixture
def thinker():
    _Thinker.seen, _Thinker.thinking = [], THINKING
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _Thinker)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_address[1]}"
    srv.shutdown()


def _plain_english(monkeypatch, capsys, base_url) -> dict:
    ig = _load("_interpret_for_plain_english", ROOT / "ansible/roles/interpret/files/interpret-ghidra.py")
    monkeypatch.setenv("LITELLM_API_KEY", "k")
    monkeypatch.setenv("LITELLM_BASE_URL", base_url)
    for var in ("LITELLM_UDS", "LITELLM_ROUTER_BASE_URL", "LITELLM_OPENAI_BASE_URL"):
        monkeypatch.delenv(var, raising=False)
    msg = {"type": "plain_english", "executive_summary": "A credential stealer.",
           "family": "unknown", "severity": "high", "filename": "x.exe", "model": "eval-haiku55"}
    monkeypatch.setattr(sys, "stdin", io.StringIO(json.dumps(msg) + "\n"))
    with pytest.raises(SystemExit):
        ig.main()
    lines = [json.loads(x) for x in capsys.readouterr().out.splitlines() if x.startswith("{")]
    return [x for x in lines if x.get("type") == "plain_english"][-1]


def test_a_thinking_model_still_writes_the_summary(monkeypatch, capsys, thinker):
    out = _plain_english(monkeypatch, capsys, thinker)
    assert _Thinker.seen[-1]["max_tokens"] > THINKING
    assert out["summary"] == "It steals your passwords."
    assert "error" not in out


def test_a_reply_with_no_text_says_why_and_keeps_its_usage(monkeypatch, capsys, thinker):
    _Thinker.thinking = 10**6                         # a model that never gets to the text
    out = _plain_english(monkeypatch, capsys, thinker)
    assert out["summary"] == ""
    assert "no text in the reply" in out["error"]
    assert out["usage"]["output_tokens"] == _Thinker.seen[-1]["max_tokens"]


def test_the_stage_passes_the_reason_and_usage_on(tmp_path):
    """run_plain_english used to drop `error`, and run-pipeline dropped usage with it."""
    # conftest puts ansible/roles/pipeline/files on sys.path.
    from stages.interpret import run_plain_english
    fake = tmp_path / "run-interpret"
    fake.write_text("#!/bin/sh\ncat >/dev/null\necho '" + json.dumps(
        {"type": "plain_english", "summary": "", "usage": {"output_tokens": 2048},
         "model_used": "eval-haiku55", "error": "no text in the reply (2048 output tokens of 2048)"})
        + "'\n")
    fake.chmod(fake.stat().st_mode | stat.S_IXUSR)
    report = {"executive_summary": {"executive_summary": "A credential stealer."}}
    out = run_plain_english(report, interpret_cmd=str(fake), interpret_enabled=True,
                            interpret_config={"plain_english_model": "eval-haiku55"})
    assert out["error"].startswith("no text in the reply")
    assert out["usage"] == {"output_tokens": 2048}
