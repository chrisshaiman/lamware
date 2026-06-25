# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""Test harness for the de-templated flat pipeline modules.

run-pipeline.py and its siblings (db_ingest, pipeline_status, ioc_extract, stages/*)
deploy flat to /opt/pipeline/. To import/run them from the repo, put that dir on the
path and point LAMWARE_PIPELINE_CONFIG at a fixture (the modules load PipelineConfig at
import; cape/db read secrets from the env).
"""
import os
import sys
from pathlib import Path

PIPELINE_FILES = (
    Path(__file__).resolve().parents[2]
    / "ansible" / "roles" / "pipeline" / "files"
)
FIXTURE_CONFIG = Path(__file__).resolve().parent / "fixtures" / "config.json"


def pytest_configure(config):
    sys.path.insert(0, str(PIPELINE_FILES))
    os.environ.setdefault("LAMWARE_PIPELINE_CONFIG", str(FIXTURE_CONFIG))
    os.environ.setdefault("CAPE_API_KEY", "dummy-test-key")
    os.environ.setdefault("PIPELINE_DB_PASSWORD", "dummy-test-pw")
