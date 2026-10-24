"""AgentShield API — Events endpoints"""
from __future__ import annotations

from fastapi import APIRouter, HTTPException, Query

from app.schemas.models import EventListResponse, SecurityEvent
from app.storage.database import list_security_events, get_security_event

router = APIRouter()


@router.get("/events", response_model=EventListResponse)
async def list_events(
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=20, ge=1, le=100),
) -> EventListResponse:
    """Returns a paginated list of security events."""
    events, total = list_security_events(page=page, page_size=page_size)
    return EventListResponse(events=events, total=total, page=page, page_size=page_size)


@router.get("/events/{event_id}", response_model=SecurityEvent)
async def get_event(event_id: str) -> SecurityEvent:
    """Returns a single security event by ID."""
    event = get_security_event(event_id)
    if not event:
        raise HTTPException(status_code=404, detail="Event not found")
    return event
