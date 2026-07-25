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
    "claude-sonnet-5": Arm("claude-sonnet-5", "claude-sonnet-5", None, 10),
}


def resolve_arm(name: str) -> Arm:
    if name not in _REGISTRY:
        raise KeyError(f"unknown arm: {name}. Known: {sorted(_REGISTRY)}")
    return _REGISTRY[name]


def parse_arms(csv: str) -> list[Arm]:
    return [resolve_arm(n.strip()) for n in csv.split(",") if n.strip()]
