# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""PDF and log downloads refuse a task_id that is not one safe path segment (#730).

Both endpoints join the database row's task_id onto reports_dir. Calls the
guard they share with the row shapes that matter.
"""
from types import SimpleNamespace

import pytest
from app.routers.analyses import _require_safe_task_dir
from fastapi import HTTPException


@pytest.mark.parametrize("task_id", ["c8138c80aa17", "v661_5b4f596d3cf5",
                                     "eval-Latrodectus-d22c9656"])
def test_a_normal_task_id_is_served(task_id):
    _require_safe_task_dir(SimpleNamespace(id=1, task_id=task_id))


@pytest.mark.parametrize("task_id", ["../../etc", "", "..", "a/b", "x\n", None])
def test_an_unsafe_task_id_is_a_404(task_id):
    with pytest.raises(HTTPException) as e:
        _require_safe_task_dir(SimpleNamespace(id=1, task_id=task_id))
    assert e.value.status_code == 404
