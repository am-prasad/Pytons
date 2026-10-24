"""AgentShield API — Health endpoint (GET /api/v1/health)"""
from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter

from app.core.config import get_settings
from app.schemas.models import ComponentStatus, ExecutionMode, HealthResponse
from app.services.groq_client import get_telemetry, verify_groq_models

router = APIRouter()


@router.get("/health", response_model=HealthResponse)
async def health() -> HealthResponse:
    """
    Returns component readiness and truthful execution mode based on actual call outcomes.
    Never exposes secrets or API keys.
    """
    settings = get_settings()
    components = []
    telemetry = get_telemetry()

    # 1. Groq Model Verification via Live Ping
    groq_ok, groq_detail = verify_groq_models()
    components.append(
        ComponentStatus(
            name="groq_llm",
            available=groq_ok,
            detail=groq_detail,
        )
    )

    # 2. Scanner (Deterministic)
    components.append(
        ComponentStatus(
            name="scanner",
            available=True,
            detail="Deterministic heuristic screening ready (<5ms).",
        )
    )

    # 3. Policy Gate
    components.append(
        ComponentStatus(
            name="policy_gate",
            available=True,
            detail="Mathematical risk scoring and egress allowlist active.",
        )
    )

    # 4. LangSmith Tracing
    components.append(
        ComponentStatus(
            name="langsmith",
            available=settings.langsmith_configured,
            detail=f"Project: {settings.langsmith_project}" if settings.langsmith_configured else "Not configured (local trace only)",
        )
    )

    # 5. Database
    db_available = False
    db_detail = "Not tested"
    try:
        from app.storage.database import get_session
        with get_session() as db:
            db.execute(__import__("sqlalchemy").text("SELECT 1"))
        db_available = True
        db_detail = "SQLite persistent storage active."
    except Exception as exc:
        db_detail = f"Unavailable: {type(exc).__name__}"

    components.append(
        ComponentStatus(name="database", available=db_available, detail=db_detail)
    )

    # Truthful Execution Mode Calculation
    if not settings.groq_configured:
        exec_mode = ExecutionMode.LOCAL_BASELINE
    elif groq_ok:
        exec_mode = ExecutionMode.FULL
    else:
        exec_mode = ExecutionMode.DEGRADED

    status = "healthy" if (exec_mode in (ExecutionMode.FULL, ExecutionMode.LOCAL_BASELINE) and db_available) else "degraded"

    return HealthResponse(
        status=status,
        execution_mode=exec_mode,
        components=components,
        timestamp=datetime.now(timezone.utc),
        judge_model=settings.groq_model,
        agent_model=settings.agent_model,
        last_call_status=telemetry.get("last_call_status"),
        last_error_class=telemetry.get("last_error_class"),
    )
