"""AgentShield API — Health endpoint (GET /api/v1/health)"""
from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter

from app.schemas.models import ComponentStatus, ExecutionMode, HealthResponse
from app.core.config import get_settings

import logging

logger = logging.getLogger(__name__)
router = APIRouter()


@router.get("/health", response_model=HealthResponse)
async def health() -> HealthResponse:
    """Returns component readiness and current execution mode. Never exposes secrets."""
    settings = get_settings()
    components = []

    # Groq
    components.append(
        ComponentStatus(
            name="groq_llm",
            available=settings.groq_configured,
            detail="Configured" if settings.groq_configured else "GROQ_API_KEY not set — using local heuristic",
        )
    )

    # LangSmith
    components.append(
        ComponentStatus(
            name="langsmith",
            available=settings.langsmith_configured,
            detail="Configured" if settings.langsmith_configured else "Not configured",
        )
    )

    # ChromaDB
    chroma_available = False
    chroma_detail = "Not tested"
    try:
        import chromadb
        client = chromadb.PersistentClient(path=settings.chroma_persist_directory)
        _ = client.heartbeat()
        chroma_available = True
        chroma_detail = "Connected"
    except Exception as exc:
        chroma_detail = f"Unavailable: {type(exc).__name__}"

    components.append(
        ComponentStatus(name="chromadb", available=chroma_available, detail=chroma_detail)
    )

    # Database
    db_available = False
    db_detail = "Not tested"
    try:
        from app.storage.database import get_session
        with get_session() as db:
            db.execute(__import__("sqlalchemy").text("SELECT 1"))
        db_available = True
        db_detail = "Connected"
    except Exception as exc:
        db_detail = f"Unavailable: {type(exc).__name__}"

    components.append(
        ComponentStatus(name="database", available=db_available, detail=db_detail)
    )

    # Determine execution mode
    all_available = settings.groq_configured
    some_degraded = not settings.groq_configured
    if all_available:
        exec_mode = ExecutionMode.FULL
    elif some_degraded:
        exec_mode = ExecutionMode.LOCAL_BASELINE
    else:
        exec_mode = ExecutionMode.DEGRADED

    all_healthy = all(c.available for c in components if c.name in ("database",))
    status = "healthy" if all_healthy else "degraded"

    return HealthResponse(
        status=status,
        execution_mode=exec_mode,
        components=components,
        timestamp=datetime.now(timezone.utc),
    )
