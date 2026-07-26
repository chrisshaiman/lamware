# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
import pytest
from lamware_eval.arms import Arm, parse_arms, resolve_arm


def test_local_arms_carry_backend_and_cycles():
    a = resolve_arm("qwen@25")
    assert a == Arm("qwen@25", "local-qwen-llamacpp-re", "local", 25)
    assert resolve_arm("qwen@10").max_tool_calls == 10


def test_cloud_arm_has_no_local_backend():
    a = resolve_arm("claude-sonnet-5")
    assert a.model == "claude-sonnet-5" and a.re_backend is None


def test_opus5_arm_is_cloud():
    a = resolve_arm("claude-opus-5")
    assert a == Arm("claude-opus-5", "claude-opus-5", None, 10)


def test_parse_arms_csv():
    arms = parse_arms("qwen@10,claude-sonnet-5")
    assert [x.name for x in arms] == ["qwen@10", "claude-sonnet-5"]


def test_unknown_arm_raises():
    with pytest.raises(KeyError):
        resolve_arm("gpt-9")


def test_depth_probe_arm_is_local_and_deep():
    """qwen@75 exists to find where findings flatten, not to fit a budget."""
    a = resolve_arm("qwen@75")
    assert a == Arm("qwen@75", "local-qwen-llamacpp-re", "local", 75)


def test_every_local_arm_uses_the_same_model():
    """Cycle count is the only variable across the qwen arms — otherwise a depth
    comparison silently conflates 'deeper' with 'different model'."""
    local = [a for a in (resolve_arm(n) for n in ("qwen@10", "qwen@25", "qwen@75"))]
    assert len({a.model for a in local}) == 1
    assert {a.re_backend for a in local} == {"local"}
    assert [a.max_tool_calls for a in local] == [10, 25, 75]
