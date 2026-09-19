# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""Repeated-detonation measurement: the instrument #518 needed and never had.

lamware_eval evaluates LLM ARMS over a frozen report.json. It never detonates.
So the entire #518 investigation ran through hand-written shell drivers on the
host -- 13 of them between 2026-09-04 and 2026-09-17 -- because there was no
code path for "run this sample N times and tell me how much the observation
varies". This is that path.

Everything here was learned the expensive way. See batch.py for the four
invariants and what each one cost.
"""
