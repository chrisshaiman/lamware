# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
import pytest

from lamware_eval.arms import resolve_arm, parse_arms, Arm


def test_local_arms_carry_backend_and_cycles():
    a = resolve_arm("qwen@25")
    assert a == Arm("qwen@25", "local-qwen-llamacpp-re", "local", 25)
    assert resolve_arm("qwen@10").max_tool_calls == 10


def test_cloud_arm_has_no_local_backend():
    a = resolve_arm("claude-sonnet-5")
    assert a.model == "claude-sonnet-5" and a.re_backend is None


def test_parse_arms_csv():
    arms = parse_arms("qwen@10,claude-sonnet-5")
    assert [x.name for x in arms] == ["qwen@10", "claude-sonnet-5"]


def test_unknown_arm_raises():
    with pytest.raises(KeyError):
        resolve_arm("gpt-9")
