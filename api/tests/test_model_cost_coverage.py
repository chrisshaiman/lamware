# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""Every model the agent may select has to have a price.

The allow-list is the operator's investigate_models (ADR-038), filtered by
MODEL_COSTS. Before that, `VALID_MODELS` (routers/investigate) and `MODEL_COSTS`
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
from app.config import DEFAULT_INVESTIGATE_MODELS, settings
from app.investigate.orchestrator import MODEL_COSTS
from app.routers import investigate as router


def test_every_selectable_model_has_a_price():
    """THE contract. Holds by construction: valid_models() drops what MODEL_COSTS
    cannot price, so an operator-listed model never bills at $0.00 per token."""
    unpriced = sorted(set(router.valid_models()) - set(MODEL_COSTS))
    assert not unpriced, unpriced


def test_an_unpriced_listed_model_is_left_out_and_named(monkeypatch, caplog):
    """ADR-038: the operator's list, minus what has no price, logged by name."""
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


def test_the_shipped_default_is_offered_whole():
    """Guards the other direction: a default that filters to nothing would satisfy
    the contract above with an allowlist of nothing."""
    assert [m.name for m in DEFAULT_INVESTIGATE_MODELS] == [
        "claude-sonnet-4-6", "claude-opus-4-6", "claude-haiku-4-5"]
    assert set(m.name for m in DEFAULT_INVESTIGATE_MODELS) <= set(MODEL_COSTS)


def test_every_price_is_a_positive_number():
    """A model priced at zero is the same silent-$0 bug with extra steps."""
    for model, price in MODEL_COSTS.items():
        assert set(price) == {"input", "output"}, model
        for leg, value in price.items():
            assert isinstance(value, (int, float)) and value > 0, f"{model}.{leg} = {value}"


# --- compute_cost: the fallback still exists, and now says so ------------

def test_a_priced_model_costs_what_the_table_says():
    from app.investigate.orchestrator import MODEL_COSTS, compute_cost
    price = MODEL_COSTS["claude-sonnet-4-6"]
    assert compute_cost("claude-sonnet-4-6", 1000, 500) == pytest.approx(
        1000 * price["input"] + 500 * price["output"])


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
def test_models_the_proxy_serves_but_we_do_not_price_are_not_selectable(model, monkeypatch):
    """The concrete drift scenario: LiteLLM serves these today. Even when the operator
    lists one, it is not selectable until it is priced."""
    monkeypatch.setattr(settings, "investigate_models", [
        SimpleNamespace(name="claude-sonnet-4-6", label="Sonnet"), SimpleNamespace(name=model, label="X")])
    assert model not in router.valid_models()
