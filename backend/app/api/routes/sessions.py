"""AgentShield API — Session endpoints"""
from fastapi import APIRouter, HTTPException

from app.schemas.models import SessionResetRequest, SessionResetResponse
from app.services.session_store import get_store

router = APIRouter()


@router.post("/sessions/reset", response_model=SessionResetResponse)
async def reset_session(body: SessionResetRequest) -> SessionResetResponse:
    """Reset a demo session's risk history."""
    store = get_store()
    existed = store.reset(body.session_id)
    return SessionResetResponse(
        session_id=body.session_id,
        cleared=existed,
        message=f"Session '{body.session_id}' cleared." if existed else "Session not found (may already be clear).",
    )
