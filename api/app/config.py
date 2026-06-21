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
    api_port: int = 8001
    api_host: str = "127.0.0.1"

    # Keycloak OIDC
    keycloak_url: str = "http://127.0.0.1:8080/auth"  # internal URL for JWKS fetch
    keycloak_issuer_url: str = "https://localhost/auth"  # external URL matching token issuer
    keycloak_realm: str = "lamware"
    keycloak_client_id: str = "lamware-web"

    # JWT audience allowlist — a token is accepted only if its aud claim
    # intersects this list. "account" is transitional (Keycloak stamps it on
    # every realm token); drop it once all live tokens carry lamware-api.
    # Override with LAMWARE_JWT_ALLOWED_AUDIENCES (JSON list).
    jwt_allowed_audiences: list[str] = ["lamware-api", "account"]

    # API docs — disable in production
    enable_docs: bool = False

    # Filesystem paths used by routers
    reports_dir: str = "/opt/pipeline/reports"
    network_monitor_status: str = "/opt/network-monitor/status.json"
    auto_feeder_state: str = "/opt/auto-feeder/state.json"
    auto_feeder_log: str = "/opt/auto-feeder/auto-feeder.log"
    pause_file: str = "/opt/pipeline/control/PAUSE"
    digest_file: str = "/opt/ntfy-alerts/latest-digest.json"
    pipeline_cmd: str = "/usr/local/bin/run-pipeline"

    # CORS — React dev server by default; extend in env file for prod WireGuard IP
    cors_origins: list[str] = ["http://localhost:3000"]

    # Investigation agent
    litellm_url: str = "http://127.0.0.1:4000"
    litellm_key: str = "sk-lamware"
    investigation_max_turns: int = 100
    investigation_cost_alert_usd: float = 2.0
    investigation_max_tool_calls_per_turn: int = 20
    sandbox_cmd: str = "/usr/local/bin/run-sandbox"
    ghidra_cmd: str = "/usr/local/bin/run-ghidra"

    model_config = {"env_prefix": "LAMWARE_"}


# Singleton — imported everywhere as `from app.config import settings`
settings = Settings()
