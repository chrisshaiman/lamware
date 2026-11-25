# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""A run's cost is LiteLLM's recorded cost of every call it made (ADR-037).

The resolver: every stage's call ids are gathered, looked up, retried while the spend
log lags, and anything it could not price is recorded, not guessed. The container
side: an httpx hook on every client records each response's LiteLLM call id, and a
stage's result carries them in `usage`, exercised end to end through the anthropic
SDK (streaming, as the agent loop calls) against the llm-stub with a LiteLLM-style
call-id header added.
"""
from __future__ import annotations

import importlib.util
import json
import socketserver
import sys
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import anthropic
import pytest
from lamware_pipeline.llm_cost import call_ids, litellm_spend_fetcher, resolve_run_cost

ROOT = Path(__file__).resolve().parents[2]


def _report(**stages):
    r = {}
    for name, usage in stages.items():
        if name == "plain_english":
            r["plain_english_usage"] = usage
        else:
            r[name] = {"usage": usage}
    return r


def test_ids_are_gathered_from_every_stage_once():
    r = _report(llm_interpretation={"input_tokens": 5, "litellm_call_ids": ["a", "b"]},
                executive_summary={"input_tokens": 1, "litellm_call_ids": ["b", "c"]},
                plain_english={"output_tokens": 2, "litellm_call_ids": ["d"]})
    assert call_ids(r) == (["a", "b", "c", "d"], [])


def test_a_stage_with_tokens_but_no_ids_is_named():
    r = _report(llm_interpretation={"input_tokens": 5}, visual_analysis={"input_tokens": 0})
    assert call_ids(r) == ([], ["llm_interpretation"])


def test_everything_resolves():
    r = _report(llm_interpretation={"input_tokens": 5, "litellm_call_ids": ["a", "b"]})
    cost = resolve_run_cost(r, {"a": 0.25, "b": 0.5}.get, sleep=lambda s: None)
    assert cost == {"source": "litellm", "usd": 0.75, "calls": 2, "resolved": 2,
                    "unresolved_call_ids": [], "stages_without_call_ids": [], "complete": True}


def test_a_lagging_spend_log_is_retried_until_it_has_the_call():
    t = [0.0]
    seen = {"a": 0}

    def fetch(cid):
        seen[cid] += 1
        return 0.1 if seen[cid] >= 3 else None

    def sleep(s):
        t[0] += s

    cost = resolve_run_cost(_report(llm_interpretation={"input_tokens": 1, "litellm_call_ids": ["a"]}),
                            fetch, deadline_s=60, poll_s=10, clock=lambda: t[0], sleep=sleep)
    assert cost["complete"] and cost["usd"] == 0.1 and seen["a"] == 3


def test_an_id_never_found_is_recorded_unresolved_not_guessed():
    t = [0.0]
    cost = resolve_run_cost(_report(llm_interpretation={"input_tokens": 1, "litellm_call_ids": ["a", "b"]}),
                            {"a": 0.2}.get, deadline_s=30, poll_s=10, clock=lambda: t[0],
                            sleep=lambda s: t.__setitem__(0, t[0] + s))
    assert cost["unresolved_call_ids"] == ["b"] and not cost["complete"] and cost["usd"] == 0.2


def test_a_stage_without_ids_makes_the_cost_incomplete():
    cost = resolve_run_cost(_report(llm_interpretation={"input_tokens": 1, "litellm_call_ids": ["a"]},
                                    executive_summary={"output_tokens": 9}),
                            {"a": 0.1}.get, sleep=lambda s: None)
    assert cost["stages_without_call_ids"] == ["executive_summary"] and not cost["complete"]


# --- the spend-log fetcher, against a fake LiteLLM --------------------------------------

class _Spend(BaseHTTPRequestHandler):
    rows: dict = {}
    auth: list = []

    def log_message(self, *a):
        pass

    def do_GET(self):
        type(self).auth.append(self.headers.get("Authorization"))
        from urllib.parse import parse_qs, urlparse
        cid = parse_qs(urlparse(self.path).query).get("request_id", [""])[0]
        # LiteLLM's row carries the PROVIDER's id as request_id and ours as litellm_call_id.
        body = json.dumps([{"request_id": "msg_x", "litellm_call_id": cid, "spend": self.rows[cid]}]
                          if cid in self.rows else []).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(body)


class _UnixHTTPServer(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True


@pytest.fixture
def spend_socket():
    """A fake LiteLLM spend log on a Unix socket, as the host serves it."""
    _Spend.rows, _Spend.auth = {"call-1": 0.0042}, []
    d = Path(tempfile.mkdtemp(prefix="spend"))     # short: AF_UNIX paths cap at 108 bytes
    path = str(d / "litellm.sock")
    srv = _UnixHTTPServer(path, _Spend)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield path
    srv.shutdown()
    srv.server_close()
    Path(path).unlink(missing_ok=True)
    d.rmdir()


def test_the_fetcher_reads_a_call_by_its_litellm_id_over_the_socket(spend_socket):
    fetch = litellm_spend_fetcher(spend_socket, "sk-spend")
    assert fetch("call-1") == 0.0042 and fetch("call-2") is None
    assert _Spend.auth[0] == "Bearer sk-spend"


def test_a_missing_socket_is_none_not_an_error(tmp_path):
    assert litellm_spend_fetcher(str(tmp_path / "absent.sock"), "k", timeout_s=1)("call-1") is None


def test_the_config_names_the_socket_litellm_serves():
    """Structural, because no test can run systemd: the path in PipelineConfig is the
    one litellm-socket.service listens on and the interpret wrapper mounts."""
    from lamware_pipeline.config import PipelineConfig
    path = PipelineConfig.model_fields["litellm_socket"].default
    roles = Path(__file__).resolve().parents[2] / "ansible" / "roles"
    unit = (roles / "litellm/templates/litellm-socket.service.j2").read_text()
    wrapper = (roles / "interpret/templates/run-interpret-wrapper.sh.j2").read_text()
    assert f"UNIX-LISTEN:{path}," in unit
    assert f"SOCK={path}\n" in wrapper


# --- the container side ------------------------------------------------------------------

def _load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    try:
        spec.loader.exec_module(mod)
    finally:
        sys.modules.pop(name, None)
    return mod


@pytest.fixture
def ig():
    return _load("_interpret_for_cost_test", ROOT / "ansible/roles/interpret/files/interpret-ghidra.py")


@pytest.fixture
def litellm_like():
    """The llm-stub, answering as LiteLLM does: with an x-litellm-call-id header."""
    stub = _load("_stub_for_cost_test", ROOT / "ansible/roles/llm-stub/files/llm_stub.py")
    counter = {"n": 0}

    class WithCallId(stub.StubHandler):
        def send_response(self, code, message=None):
            super().send_response(code, message)
            counter["n"] += 1
            self.send_header("x-litellm-call-id", f"call-{counter['n']}")

    srv = ThreadingHTTPServer(("127.0.0.1", 0), WithCallId)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_address[1]}"
    srv.shutdown()


def test_every_streamed_and_plain_call_is_recorded_through_our_client(ig, litellm_like):
    cli = anthropic.Anthropic(base_url=litellm_like, api_key="k", http_client=ig.http_client())
    ig.create_message(cli, model="stub", max_tokens=20, messages=[{"role": "user", "content": "x"}])
    cli.messages.create(model="stub", max_tokens=20, messages=[{"role": "user", "content": "y"}])
    assert ig.LITELLM_CALL_IDS == ["call-1", "call-2"]


def test_a_stage_result_carries_the_ids_and_per_call_events_do_not(ig):
    ig.LITELLM_CALL_IDS[:] = ["call-1", "call-2"]
    final = ig.with_call_ids({"type": "final", "usage": {"input_tokens": 3}})
    assert final["usage"] == {"input_tokens": 3, "litellm_call_ids": ["call-1", "call-2"]}
    for kind in ("turn", "stream", "request_result"):
        assert "litellm_call_ids" not in ig.with_call_ids({"type": kind, "usage": {"input_tokens": 1}})["usage"]
    ig.LITELLM_CALL_IDS[:] = []
    assert ig.with_call_ids({"type": "final", "usage": {"input_tokens": 3}}) == \
        {"type": "final", "usage": {"input_tokens": 3}}


def test_every_client_the_container_builds_has_the_hook():
    """On the syntax tree, not the text (comments mention httpx.Client too):
    every httpx.Client(...) CALL is inside http_client(), and both SDK clients'
    http_client is assigned unconditionally, so no branch builds a client without
    the hook."""
    import ast
    tree = ast.parse((ROOT / "ansible/roles/interpret/files/interpret-ghidra.py").read_text())
    parents = {}
    for node in ast.walk(tree):
        for child in ast.iter_child_nodes(node):
            parents[child] = node

    def enclosing(node, kinds):
        while node in parents:
            node = parents[node]
            if isinstance(node, kinds):
                return node
        return None

    calls = [n for n in ast.walk(tree) if isinstance(n, ast.Call)
             and isinstance(n.func, ast.Attribute) and n.func.attr == "Client"
             and isinstance(n.func.value, ast.Name) and n.func.value.id == "httpx"]
    assert calls, "no httpx.Client call found: the check would pass vacuously"
    for c in calls:
        fn = enclosing(c, ast.FunctionDef)
        assert fn is not None and fn.name == "http_client", f"httpx.Client at line {c.lineno} bypasses the hook"
    hooks = [c for c in calls if any(k.arg == "event_hooks" for k in c.keywords)]
    assert hooks == calls

    for target in ("client_kwargs", "summary_kwargs"):
        assigns = [n for n in ast.walk(tree) if isinstance(n, ast.Assign)
                   and any(isinstance(t, ast.Subscript) and isinstance(t.value, ast.Name)
                           and t.value.id == target and isinstance(t.slice, ast.Constant)
                           and t.slice.value == "http_client" for t in n.targets)]
        assert len(assigns) == 1, target
        assert enclosing(assigns[0], (ast.If,)) is None, f"{target}['http_client'] is conditional"


@pytest.mark.parametrize("func", ["run_pipeline", "run_replay"])
def test_the_cost_record_is_resolved_before_the_report_file_is_written(func):
    """Structural, because no test can run a detonation: found on the host, where the
    first stub run's report.json had no llm_cost because the write came first."""
    import ast
    src = (Path(__file__).resolve().parents[2]
           / "ansible/roles/pipeline/files/run-pipeline.py").read_text()
    fn = next(n for n in ast.walk(ast.parse(src))
              if isinstance(n, ast.FunctionDef) and n.name == func)

    def lines(pred):
        return sorted(n.lineno for n in ast.walk(fn) if pred(n))
    resolved = lines(lambda n: isinstance(n, ast.Call)
                     and getattr(n.func, "id", "") == "resolve_llm_cost")
    writes = lines(lambda n: isinstance(n, ast.Call)
                   and getattr(n.func, "id", "") == "write_report")
    assert resolved and writes, f"{func}: expected resolve_llm_cost and write_report calls"
    assert resolved[0] < writes[-1], f"{func}: the report is written before its cost is resolved"
    ingests = lines(lambda n: isinstance(n, ast.Call) and getattr(n.func, "id", "") == "ingest_to_db")
    assert all(resolved[0] < i for i in ingests), f"{func}: ingested before the cost is resolved"
