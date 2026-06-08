# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
#
# FastAPI application entrypoint.
#
# Port 8001, serves the React frontend via nginx reverse proxy.
#
# Run locally:
#   cd api
#   LAMWARE_DB_PASSWORD=... uvicorn app.main:app --reload --port 8001

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.config import settings

app = FastAPI(
    title="lamware API",
    description=(
        "REST API for the lamware malware analysis platform. "
        "Serves analysis data, IOCs, MITRE techniques, and pipeline controls."
    ),
    version="0.1.0",
    docs_url="/docs" if settings.enable_docs else None,
    redoc_url="/redoc" if settings.enable_docs else None,
    openapi_url="/openapi.json" if settings.enable_docs else None,
)

# CORS — allows the React dev server (localhost:3000) and any additional origins
# configured via LAMWARE_CORS_ORIGINS (e.g. production WireGuard IP).
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "PATCH"],
    allow_headers=["Content-Type", "Authorization"],
)

# ---------------------------------------------------------------------------
# Health endpoint — no auth, used by systemd / load balancer checks
# ---------------------------------------------------------------------------


@app.get("/health", tags=["health"])
async def health() -> dict:
    """Returns OK. No database check — just confirms the process is alive."""
    return {"status": "ok", "service": "lamware-api"}


# ---------------------------------------------------------------------------
# API routers — added here as each task is completed
# ---------------------------------------------------------------------------

from app.routers import analyses, iocs, techniques, families  # noqa: E402
from app.routers import pipeline, alerts, stats, feeder, samples  # noqa: E402
from app.routers import evasions, spend  # noqa: E402
from app.routers import ws  # noqa: E402

app.include_router(analyses.router)
app.include_router(iocs.router)
app.include_router(techniques.router)
app.include_router(families.router)
app.include_router(pipeline.router)
app.include_router(alerts.router)
app.include_router(stats.router)
app.include_router(feeder.router)
app.include_router(samples.router)
app.include_router(evasions.router)
app.include_router(spend.router)
app.include_router(ws.router)


# ---------------------------------------------------------------------------
# Startup / shutdown — WebSocket PG listener
# ---------------------------------------------------------------------------


@app.on_event("startup")
async def _startup():
    import logging
    from app.auth import fetch_jwks
    from app.routers.ws import start_pg_listener
    try:
        await fetch_jwks()
    except Exception as e:
        logging.getLogger(__name__).warning(
            "JWKS fetch failed on startup: %s (JWT auth unavailable until Keycloak is reachable)", e
        )
    await start_pg_listener()


@app.on_event("shutdown")
async def _shutdown():
    from app.routers.ws import stop_pg_listener
    await stop_pg_listener()
