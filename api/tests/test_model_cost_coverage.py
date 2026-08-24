# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""Every model the agent may select has to have a price.

`VALID_MODELS` (routers/investigate) and `MODEL_COSTS` (investigate/orchestrator)
were two hand-maintained lists in two modules. They agreed, and nothing made them.
A model in the allowlist but not the cost table bills at $0.00 per token, because
the lookup fell back to `{"input": 0.0, "output": 0.0}` — which is also what a
genuinely free local model costs, so the two are indistinguishable in the
recorded figure. `investigation_cost_alert_usd` is an alert threshold and not a
cap, so nothing downstream bounds the spend either.

Drift was the likely path, not an exotic one: the proxy already serves
claude-sonnet-5 and claude-opus-5, and adding a name to the allowlist is how you
would turn one on.
"""
import ast
import logging
from pathlib import Path

import app.routers.investigate
import pytest
from app.investigate.orchestrator import MODEL_COSTS
from app.routers.investigate import VALID_MODELS


def test_every_selectable_model_has_a_price():
    """THE contract. Fails the moment someone adds a model to one list only."""
    unpriced = sorted(set(VALID_MODELS) - set(MODEL_COSTS))
    assert not unpriced, (
        f"{unpriced} can be selected but has no MODEL_COSTS entry, so its "
        f"tokens would be billed at $0.00 and recorded as though free")


def test_the_allowlist_is_derived_rather_than_restated():
    """Deriving is what makes the test above unfailable by construction, so the
    derivation itself is the thing to pin — set equality cannot do it, because a
    hardcoded list that still happens to agree satisfies set equality exactly as
    well as a derived one. That is the state this bug started in.

    Checked against the parsed AST rather than the source text: a comment
    mentioning MODEL_COSTS, or the name appearing anywhere else in the module,
    would satisfy a grep. Only the assignment's own expression counts.
    """
    tree = ast.parse(Path(app.routers.investigate.__file__).read_text(encoding="utf-8"))
    assigns = [
        node for node in tree.body
        if isinstance(node, ast.Assign)
        and any(isinstance(t, ast.Name) and t.id == "VALID_MODELS" for t in node.targets)
    ]
    assert len(assigns) == 1, f"expected one VALID_MODELS assignment, found {len(assigns)}"
    value = assigns[0].value
    assert not isinstance(value, (ast.List, ast.Tuple, ast.Set)), (
        "VALID_MODELS is a literal collection again — it must be derived from "
        "MODEL_COSTS, or the two lists can drift apart the way they did before")
    referenced = {n.id for n in ast.walk(value) if isinstance(n, ast.Name)}
    assert "MODEL_COSTS" in referenced, (
        f"VALID_MODELS is computed from {sorted(referenced)}, not MODEL_COSTS")


def test_the_expected_models_are_still_present():
    """Guards the other direction: deriving from an accidentally-emptied table
    would satisfy every assertion above with an allowlist of nothing."""
    for model in ("claude-sonnet-4-6", "claude-opus-4-6", "claude-haiku-4-5"):
        assert model in VALID_MODELS


def test_every_price_is_a_positive_number():
    """A model priced at zero is the same silent-$0 bug with extra steps."""
    for model, price in MODEL_COSTS.items():
        assert set(price) == {"input", "output"}, model
        for leg, value in price.items():
            assert isinstance(value, (int, float)) and value > 0, f"{model}.{leg} = {value}"


def test_valid_models_are_strings():
    assert VALID_MODELS and all(isinstance(m, str) for m in VALID_MODELS)


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
def test_models_the_proxy_serves_but_we_do_not_price_are_not_selectable(model):
    """The concrete drift scenario: LiteLLM serves these today. Until they are
    priced, they must not be selectable."""
    assert model not in VALID_MODELS
