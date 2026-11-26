"""The daily digest's highlights go through LiteLLM's router (ADR-038, PR 4).

The digest posted to the /anthropic passthrough, which forwards the alias straight
to Anthropic: once the summary model became local, every morning's request got
`404 not_found_error: model: local-qwen-llamacpp` (LiteLLM's spend log, from
2026-11-16) and the digest went out without highlights, silently.

The real template is rendered and executed (psycopg2 stubbed; nothing here touches a
database) against a fake LiteLLM that records each request and answers in the wire
the request used.
"""
import json
import logging
import sys
import threading
import types
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

jinja2 = pytest.importorskip("jinja2")
pytest.importorskip("requests")

ROOT = Path(__file__).resolve().parents[1]
DIGEST = ROOT / "ansible/roles/ntfy-alerts/templates/daily-digest.py.j2"


class _LiteLLM(BaseHTTPRequestHandler):
    seen: list = []
    status = 200
    text = "- One new family."

    def log_message(self, *a):
        pass

    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        type(self).seen.append((self.path, body, dict(self.headers)))
        if self.status != 200:
            out = {"error": {"type": "not_found_error", "message": "model: x"}}
        elif self.path == "/v1/chat/completions":
            out = {"choices": [{"message": {"content": self.text}}],
                   "usage": {"prompt_tokens": 10, "completion_tokens": 5}}
        else:   # Anthropic wire: a thinking model's first block is the thinking
            out = {"content": [{"type": "thinking", "thinking": ""}, {"type": "text", "text": self.text}],
                   "usage": {"input_tokens": 10, "output_tokens": 5}}
        data = json.dumps(out).encode()
        self.send_response(self.status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("x-litellm-call-id", "call-1")
        self.end_headers()
        self.wfile.write(data)


@pytest.fixture
def litellm():
    _LiteLLM.seen, _LiteLLM.status, _LiteLLM.text = [], 200, "- One new family."
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _LiteLLM)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield srv.server_address[1]
    srv.shutdown()


def _digest(monkeypatch, port: int, model: str) -> dict:
    fake = types.ModuleType("psycopg2")
    fake.extras = types.ModuleType("psycopg2.extras")
    monkeypatch.setitem(sys.modules, "psycopg2", fake)
    monkeypatch.setitem(sys.modules, "psycopg2.extras", fake.extras)
    ntfy = types.ModuleType("ntfy_notify")      # the alert sender; not under test here
    ntfy.defang_ioc = lambda value, _type=None: value
    ntfy.send_alert = lambda *a, **k: None
    monkeypatch.setitem(sys.modules, "ntfy_notify", ntfy)
    env = jinja2.Environment()  # noqa: S701 - rendering Python, not HTML
    env.filters["mandatory"] = lambda v: v          # Ansible's; every value is supplied below
    env.filters["to_json"] = json.dumps
    src = env.from_string(DIGEST.read_text()).render(
        litellm_scoped={"digest": "sk-digest"}, litellm_port=port, interpret_summary_model=model,
        ntfy_install_dir="/nonexistent",
        pipeline_db_password="x", pipeline_db_host="h", pipeline_db_name="d", pipeline_db_user="u")
    ns = {"__name__": "daily_digest_under_test"}
    exec(compile(src, "daily-digest.py", "exec"), ns)  # noqa: S102
    return ns


def _stats():
    return {"today_count": 2, "families": {"QuasarRAT": 1}, "severities": {"high": 1},
            "total_cost": 0.0, "weekly_cost": 0.0, "evasion_count": 0, "first_seen_families": [],
            "family_trending": {}, "shared_iocs": [], "top_techniques": [],
            "plain_english_summaries": [{"severity": "high", "family": "QuasarRAT", "summary": "s"}]}


def test_a_local_model_takes_the_openai_leg_with_thinking_off(monkeypatch, litellm):
    ns = _digest(monkeypatch, litellm, "local-qwen-llamacpp")
    assert ns["generate_highlights"](_stats()) == "- One new family."
    path, body, headers = _LiteLLM.seen[-1]
    assert path == "/v1/chat/completions"
    assert body["chat_template_kwargs"] == {"enable_thinking": False}
    assert body["max_tokens"] >= 1024 and headers["Authorization"] == "Bearer sk-digest"


def test_a_cloud_model_takes_the_router_not_the_passthrough(monkeypatch, litellm):
    ns = _digest(monkeypatch, litellm, "claude-haiku-4-5")
    assert ns["generate_highlights"](_stats()) == "- One new family."   # not the thinking block
    path, body, _ = _LiteLLM.seen[-1]
    assert path == "/v1/messages" and "chat_template_kwargs" not in body


@pytest.mark.parametrize("model", ["local-qwen-llamacpp", "claude-haiku-4-5"])
def test_no_request_goes_to_the_passthrough(monkeypatch, litellm, model):
    ns = _digest(monkeypatch, litellm, model)
    ns["generate_highlights"](_stats())
    assert not [p for p, _, _ in _LiteLLM.seen if p.startswith("/anthropic")]


def test_a_failure_is_logged_with_its_status_not_swallowed(monkeypatch, litellm, caplog):
    _LiteLLM.status = 404
    ns = _digest(monkeypatch, litellm, "local-qwen-llamacpp")
    with caplog.at_level(logging.ERROR, logger="daily-digest"):
        assert ns["generate_highlights"](_stats()) == ""
    assert any("HTTP 404 not_found_error" in r.getMessage() for r in caplog.records)


def test_a_reply_with_no_text_is_logged(monkeypatch, litellm, caplog):
    _LiteLLM.text = ""
    ns = _digest(monkeypatch, litellm, "claude-haiku-4-5")
    with caplog.at_level(logging.ERROR, logger="daily-digest"):
        assert ns["generate_highlights"](_stats()) == ""
    assert any("no text in the reply" in r.getMessage() for r in caplog.records)
