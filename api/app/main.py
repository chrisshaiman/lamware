# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
#
# FastAPI application entrypoint.
#
# Port 8001, runs alongside the Flask dashboard (port 5000).
# Routers for analyses, iocs, techniques, etc. will be added here as they
# are implemented in subsequent tasks.
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
    # /docs (Swagger UI) and /redoc are public — no auth required for discovery
    docs_url="/docs",
    redoc_url="/redoc",
)

# CORS — allows the React dev server (localhost:3000) and any additional origins
# configured via LAMWARE_CORS_ORIGINS (e.g. production WireGuard IP).
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
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

from app.routers import analyses  # noqa: E402

app.include_router(analyses.router, prefix="/api/analyses", tags=["analyses"])

# Routers added in subsequent tasks:
# from app.routers import iocs, techniques, families
# from app.routers import pipeline, alerts, stats, feeder, samples
#
# app.include_router(iocs.router,        prefix="/api/iocs",             tags=["iocs"])
# app.include_router(techniques.router,  prefix="/api/techniques",       tags=["techniques"])
# app.include_router(families.router,    prefix="/api/families",         tags=["families"])
# app.include_router(pipeline.router,    prefix="/api/pipeline",         tags=["pipeline"])
# app.include_router(alerts.router,      prefix="/api/alerts",           tags=["alerts"])
# app.include_router(stats.router,       prefix="/api/stats",            tags=["stats"])
# app.include_router(feeder.router,      prefix="/api/feeder",           tags=["feeder"])
# app.include_router(samples.router,     prefix="/api/samples",          tags=["samples"])
