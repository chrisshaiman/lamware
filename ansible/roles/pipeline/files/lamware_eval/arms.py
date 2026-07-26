# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""Named model/config arms for the eval harness. Each maps to an interpret cfg override."""
from dataclasses import dataclass

_LOCAL_MODEL = "local-qwen-llamacpp-re"


@dataclass
class Arm:
    name: str
    model: str
    re_backend: str | None  # "local" routes via the LiteLLM router; None = cloud passthrough
    max_tool_calls: int


_REGISTRY: dict[str, Arm] = {
    "qwen@10": Arm("qwen@10", _LOCAL_MODEL, "local", 10),
    "qwen@25": Arm("qwen@25", _LOCAL_MODEL, "local", 25),
    # Depth probe: let the local model run to its natural stopping point rather than
    # to a budget. Local inference is $0, so the question "how deep does it go before
    # findings flatten?" is answerable here in a way it never was on a metered model.
    # NB: the cap is approximate — parallel tool calls are counted per-block after
    # increment, so a run can overshoot it.
    # 30 is the depth-probe target after the two ceilings found on 2026-07-27:
    # context (fixed by --ctx-size 65536) and then request latency (fixed by
    # streaming). Both probes died around 20-22 calls WITHOUT producing an analysis,
    # so no run has yet shown whether cycles beyond ~15 add anything. 30 is chosen to
    # clear that unknown while still being likely to COMPLETE — an incomplete run
    # answers nothing, which is the lesson of qwen@75.
    "qwen@30": Arm("qwen@30", _LOCAL_MODEL, "local", 30),
    "qwen@75": Arm("qwen@75", _LOCAL_MODEL, "local", 75),
    "claude-sonnet-5": Arm("claude-sonnet-5", "claude-sonnet-5", None, 10),
    "claude-opus-5": Arm("claude-opus-5", "claude-opus-5", None, 10),
}


def resolve_arm(name: str) -> Arm:
    if name not in _REGISTRY:
        raise KeyError(f"unknown arm: {name}. Known: {sorted(_REGISTRY)}")
    return _REGISTRY[name]


def parse_arms(csv: str) -> list[Arm]:
    return [resolve_arm(n.strip()) for n in csv.split(",") if n.strip()]
