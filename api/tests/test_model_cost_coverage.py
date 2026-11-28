# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""Every model the agent may select has to have a price.

The allow-list is the operator's investigate_models (ADR-038), filtered by the
models LiteLLM states a price for (pricing.py). MODEL_COSTS, the hand-kept table
that once did this, is gone. Before the operator list, `VALID_MODELS` (routers/investigate) and `MODEL_COSTS`
(investigate/orchestrator) were two hand-maintained lists in two modules. They agreed, and nothing made them.
A model in the allowlist but not the cost table bills at $0.00 per token, because
the lookup fell back to `{"input": 0.0, "output": 0.0}` — which is also what a
genuinely free local model costs, so the two are indistinguishable in the
recorded figure. `investigation_cost_alert_usd` is an alert threshold and not a
cap, so nothing downstream bounds the spend either.

Drift was the likely path, not an exotic one: the proxy already serves
claude-sonnet-5 and claude-opus-5, and adding a name to the allowlist is how you
would turn one on.
"""
import logging
from types import SimpleNamespace

import pytest
from app.config import settings
from app.investigate.pricing import Price
from app.routers import investigate as router

LITELLM_PRICES = {"claude-sonnet-4-6": Price(3e-6, 15e-6), "claude-opus-4-6": Price(5e-6, 25e-6),
                  "claude-haiku-4-5": Price(1e-6, 5e-6)}


@pytest.fixture(autouse=True)
def _litellm_prices(monkeypatch):
    """LiteLLM's prices as /v1/model/info would give them; no LiteLLM in this job.

    Patched on the `pricing` each module under test HOLDS: other test files exec these
    modules against stubs, so the import order decides which object that is."""
    from app.investigate import orchestrator
    for holder in (router, orchestrator):
        monkeypatch.setattr(holder.pricing, "prices", lambda: dict(LITELLM_PRICES))


def test_every_selectable_model_has_a_price():
    """THE contract. Holds by construction: valid_models() drops what LiteLLM does not
    price, so an operator-listed model never bills at $0.00 per token."""
    unpriced = sorted(set(router.valid_models()) - set(LITELLM_PRICES))
    assert not unpriced, unpriced


def test_an_unpriced_listed_model_is_left_out_and_named(monkeypatch, caplog):
    """ADR-038: the operator's list, minus what LiteLLM has no price for, logged by name."""
    monkeypatch.setattr(settings, "investigate_models", [
        SimpleNamespace(name="claude-sonnet-4-6", label="Sonnet"),
        SimpleNamespace(name="claude-sonnet-9", label="Future")])
    with caplog.at_level(logging.WARNING, logger=router.log.name):
        assert router.valid_models() == ["claude-sonnet-4-6"]
    assert any("claude-sonnet-9" in r.getMessage() for r in caplog.records)


def test_the_operator_list_sets_the_order_and_the_labels(monkeypatch):
    monkeypatch.setattr(settings, "investigate_models", [
        SimpleNamespace(name="claude-haiku-4-5", label="Fast"),
        SimpleNamespace(name="claude-opus-4-6", label="Deep")])
    assert router.investigate_models() == [{"name": "claude-haiku-4-5", "label": "Fast"},
                                           {"name": "claude-opus-4-6", "label": "Deep"}]


def test_with_litellm_unreadable_nothing_is_offered(monkeypatch):
    """pricing.prices() is empty when LiteLLM cannot be read and nothing was read
    before: fail closed, rather than offer models nobody can price."""
    monkeypatch.setattr(router.pricing, "prices", lambda: {})
    assert router.valid_models() == []


# --- compute_cost: the fallback still exists, and now says so ------------

def test_a_priced_model_costs_what_litellm_says():
    from app.investigate.orchestrator import compute_cost
    price = LITELLM_PRICES["claude-sonnet-4-6"]
    assert compute_cost("claude-sonnet-4-6", 1000, 500) == pytest.approx(
        1000 * price.input + 500 * price.output)


def test_an_unpriced_model_logs_a_warning_naming_the_model_and_the_tokens(caplog):
    """The silence is the bug, so the warning is the fix. Deriving the allowlist
    makes this branch unreachable through the router; it is kept for anything
    that reaches the orchestrator another way."""
    from app.investigate import orchestrator

    with caplog.at_level(logging.WARNING, logger=orchestrator.__name__):
        cost = orchestrator.compute_cost("claude-sonnet-5", 1_000_000, 2_000_000)

    assert cost == 0.0, "there is no price to apply, so zero is the only answer"
    assert len(caplog.records) == 1, "exactly one warning, not none and not a flood"
    message = caplog.records[0].getMessage()
    assert "claude-sonnet-5" in message, "an operator has to know WHICH model"
    assert "1000000" in message and "2000000" in message, (
        "and how much went unpriced — the token counts are the whole signal")


def test_a_priced_model_logs_nothing(caplog):
    """The mirror. A warning on every turn would be noise nobody reads."""
    from app.investigate import orchestrator

    with caplog.at_level(logging.WARNING, logger=orchestrator.__name__):
        orchestrator.compute_cost("claude-haiku-4-5", 10, 10)
    assert caplog.records == []


def test_zero_tokens_cost_zero_without_a_warning():
    from app.investigate.orchestrator import compute_cost
    assert compute_cost("claude-opus-4-6", 0, 0) == 0.0


@pytest.mark.parametrize("model", ["claude-sonnet-5", "claude-opus-5", "gpt-4o"])
def test_models_litellm_does_not_price_are_not_selectable(model, monkeypatch):
    """Even when the operator lists one, a model is not selectable until LiteLLM
    states a price for it."""
    monkeypatch.setattr(settings, "investigate_models", [
        SimpleNamespace(name="claude-sonnet-4-6", label="Sonnet"), SimpleNamespace(name=model, label="X")])
    assert model not in router.valid_models()
