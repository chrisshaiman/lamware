# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
#
# Configuration — loads settings from environment variables or a config file.
# All variables are prefixed with LAMWARE_ (e.g. LAMWARE_DB_PASSWORD).
# Ansible writes the env file at deploy time; in dev, export vars directly.

from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    # Database connection
    db_host: str = "127.0.0.1"
    db_port: int = 5432
    db_name: str = "malware_analysis"
    db_user: str = "pipeline"
    db_password: str = ""

    # API server
    api_key: str = ""        # empty string = dev mode (no auth enforced)
    api_port: int = 8001
    api_host: str = "0.0.0.0"

    # Filesystem paths used by routers
    reports_dir: str = "/opt/pipeline/reports"
    network_monitor_status: str = "/opt/network-monitor/status.json"
    auto_feeder_state: str = "/opt/auto-feeder/state.json"
    auto_feeder_log: str = "/opt/auto-feeder/auto-feeder.log"
    pause_file: str = "/opt/pipeline/PAUSE"
    digest_file: str = "/opt/ntfy-alerts/latest-digest.json"
    pipeline_cmd: str = "/usr/local/bin/run-pipeline"

    # CORS — React dev server by default; extend in env file for prod WireGuard IP
    cors_origins: list[str] = ["http://localhost:3000"]

    model_config = {"env_prefix": "LAMWARE_"}


# Singleton — imported everywhere as `from app.config import settings`
settings = Settings()
