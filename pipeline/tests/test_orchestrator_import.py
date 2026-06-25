# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""Real end-to-end gate: the de-templated orchestrator imports + runs --help with no
live host. Exercises the full module-constant block + PipelineConfig.load + every
sibling/stage import + transitive third-party (requests, psycopg2) under a fixture
config. Supersedes the 2b-3 py_compile stand-in now that the graph imports fully.
"""
import os
import subprocess
import sys
from pathlib import Path

FILES = Path(__file__).resolve().parents[2] / "ansible" / "roles" / "pipeline" / "files"
FIXTURE = Path(__file__).resolve().parent / "fixtures" / "config.json"


def test_run_pipeline_help_runs():
    env = {
        **os.environ,
        "LAMWARE_PIPELINE_CONFIG": str(FIXTURE),
        "CAPE_API_KEY": "dummy",
        "PIPELINE_DB_PASSWORD": "dummy",
    }
    proc = subprocess.run(
        [sys.executable, "run-pipeline.py", "--help"],
        cwd=str(FILES), env=env, capture_output=True, text=True, timeout=60,
    )
    assert proc.returncode == 0, f"--help failed:\nSTDOUT:\n{proc.stdout}\nSTDERR:\n{proc.stderr}"
    assert "usage: run-pipeline" in proc.stdout
