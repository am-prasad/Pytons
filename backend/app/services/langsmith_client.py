"""
AgentShield LangSmith Service
Verifies LangSmith connection, exports runs, and ensures real telemetry tracing.
"""
from __future__ import annotations

import logging
import os
import time
from typing import Any, Dict, Optional, Tuple

from app.core.config import get_settings

logger = logging.getLogger(__name__)


def get_langsmith_client():
    settings = get_settings()
    if not settings.langsmith_configured:
        return None
    try:
        from langsmith import Client
        return Client(
            api_key=settings.langsmith_api_key,
            api_url=settings.langsmith_endpoint,
        )
    except Exception as exc:
        logger.warning("Could not initialize LangSmith Client: %s", exc)
        return None


def verify_langsmith_connection() -> Tuple[bool, str]:
    """
    Attempts a lightweight call to LangSmith API to verify API key and project availability.
    """
    settings = get_settings()
    if not settings.langsmith_configured:
        return False, "LANGSMITH_API_KEY is not configured in backend/.env"

    client = get_langsmith_client()
    if not client:
        return False, "Failed to instantiate LangSmith client (check dependencies)"

    try:
        import uuid
        from datetime import datetime, timezone
        project_name = settings.clean_langsmith_project
        run_id = uuid.uuid4()
        now = datetime.now(timezone.utc)
        client.create_run(
            id=run_id,
            name="AgentShield_Heartbeat_Verification",
            run_type="chain",
            inputs={"service": "AgentShield", "check": "LangSmith Tracing Online"},
            start_time=now,
            project_name=project_name,
            tags=["agentshield", "connectivity_verified"],
        )
        client.update_run(
            run_id=run_id,
            outputs={"status": "active", "telemetry_online": True},
            end_time=datetime.now(timezone.utc),
        )
        return True, f"Connected to LangSmith (Project: '{project_name}')"
    except Exception as exc:
        err_msg = str(exc)
        logger.error("LangSmith connection verification failed: %s", err_msg)
        return False, f"LangSmith error: {err_msg[:140]}"
