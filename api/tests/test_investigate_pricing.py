# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""pricing.py reads LiteLLM's prices (ADR-037, ADR-038).

Against a fake LiteLLM on loopback that serves /v1/model/info the way LiteLLM does
(measured on the host 2026-11-28: model_info.input_cost_per_token and
output_cost_per_token per model the key may call).
"""
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest
from app.config import settings
from app.investigate import pricing


class _LiteLLM(BaseHTTPRequestHandler):
    data: list = []
    status = 200
    auth: list = []

    def log_message(self, *a):
        pass

    def do_GET(self):
        type(self).auth.append(self.headers.get("Authorization"))
        body = json.dumps({"data": self.data}).encode()
        self.send_response(self.status)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(body)


def _model(name, cin, cout):
    return {"model_name": name, "model_info": {"input_cost_per_token": cin, "output_cost_per_token": cout}}


@pytest.fixture
def litellm(monkeypatch):
    _LiteLLM.data, _LiteLLM.status, _LiteLLM.auth = [], 200, []
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _LiteLLM)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    monkeypatch.setattr(settings, "litellm_url", f"http://127.0.0.1:{srv.server_address[1]}")
    monkeypatch.setattr(settings, "litellm_investigate_key", "sk-investigate")
    pricing.clear_cache()
    yield _LiteLLM
    pricing.clear_cache()
    srv.shutdown()


def test_stated_prices_are_read_with_the_panels_own_key(litellm):
    litellm.data = [_model("claude-sonnet-4-6", 3e-6, 15e-6), _model("local-ollama", 0, 0)]
    assert pricing.prices() == {"claude-sonnet-4-6": pricing.Price(3e-6, 15e-6),
                                "local-ollama": pricing.Price(0.0, 0.0)}   # free by declaration
    assert litellm.auth == ["Bearer sk-investigate"]


@pytest.mark.parametrize("cin, cout", [(None, None), (3e-6, None), (-1, 1e-6), ("3e-6", 1e-6)])
def test_a_model_without_two_stated_prices_is_not_priced(litellm, cin, cout):
    litellm.data = [_model("claude-x", cin, cout)]
    assert pricing.prices() == {}


def test_prices_are_cached(litellm):
    litellm.data = [_model("claude-sonnet-4-6", 3e-6, 15e-6)]
    pricing.prices()
    litellm.data = []
    assert "claude-sonnet-4-6" in pricing.prices() and len(litellm.auth) == 1


def test_an_unreachable_litellm_keeps_the_last_prices_then_fails_closed(litellm, monkeypatch):
    litellm.data = [_model("claude-sonnet-4-6", 3e-6, 15e-6)]
    pricing.prices()
    monkeypatch.setattr(pricing, "CACHE_SECONDS", 0)
    litellm.status = 500
    assert "claude-sonnet-4-6" in pricing.prices()          # last prices read
    pricing.clear_cache()
    assert pricing.prices() == {}                            # none read: nothing priced
