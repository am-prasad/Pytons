"""AgentShield API Router — Mounts all v1 routes."""
from fastapi import APIRouter

from app.api.routes import analyze, documents, evaluation, events, health, sessions, tools

router = APIRouter(prefix="/api/v1")

router.include_router(health.router, tags=["Health"])
router.include_router(documents.router, tags=["Documents & Agents"])
router.include_router(analyze.router, tags=["Analysis"])
router.include_router(sessions.router, tags=["Sessions"])
router.include_router(tools.router, tags=["Tools"])
router.include_router(events.router, tags=["Events"])
router.include_router(evaluation.router, tags=["Evaluation"])
