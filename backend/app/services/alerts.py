"""
AgentShield Alerting & Approval Dispatcher
Handles multi-channel security alert fan-out:
1. End-user sanitized notices
2. Security team Slack webhooks
3. Automation signed HMAC-SHA256 JSON webhooks
4. Human-in-the-loop approval requests (/api/v1/approvals)
5. Audit trail in data/audit_alerts.jsonl
Delivery failures are captured safely without interrupting pipeline execution.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import httpx

from app.core.config import get_settings
from app.schemas.models import AlertEvent, ApprovalRequest, RiskCategory

logger = logging.getLogger(__name__)

# In-memory stores for active alerts & pending approvals
_ALERTS_LOG: List[AlertEvent] = []
_PENDING_APPROVALS: Dict[str, ApprovalRequest] = {}


def create_and_dispatch_alert(
    severity: RiskCategory,
    checkpoint: str,
    source_ref: str,
    evidence: List[str],
    blocked_action: Optional[str] = None,
    recommendation: str = "Quarantine source and verify agent prompt boundaries.",
    requires_approval: bool = False,
    tool_params: Optional[Dict[str, Any]] = None,
    session_id: Optional[str] = None,
    risk_score: float = 0.0,
) -> Tuple[AlertEvent, Optional[ApprovalRequest]]:
    """
    Constructs an AlertEvent, registers any human approval request,
    and dispatches asynchronously to configured webhooks.
    """
    settings = get_settings()
    alert_id = str(uuid.uuid4())
    approval_req: Optional[ApprovalRequest] = None

    # Sanitized user-facing notice (no regexes or bypass hints)
    if blocked_action:
        user_notice = f"The requested action '{blocked_action}' was prevented by security policy."
    elif severity in (RiskCategory.CRITICAL, RiskCategory.HIGH):
        user_notice = "Potentially malicious instructions in untrusted content were neutralized."
    else:
        user_notice = "Content has been flagged for human security review."

    alert = AlertEvent(
        alert_id=alert_id,
        timestamp=datetime.now(timezone.utc),
        severity=severity,
        checkpoint=checkpoint,
        source_ref=source_ref,
        evidence=evidence[:4],
        blocked_action=blocked_action,
        recommendation=recommendation,
        user_notice=user_notice,
        status="pending_approval" if requires_approval else "delivered",
    )
    _ALERTS_LOG.append(alert)

    # Human approval path
    if requires_approval and blocked_action:
        approval_id = f"appr-{uuid.uuid4().hex[:8]}"
        approval_req = ApprovalRequest(
            approval_id=approval_id,
            timestamp=datetime.now(timezone.utc),
            tool_name=blocked_action,
            parameters=tool_params or {},
            session_id=session_id,
            risk_score=risk_score,
            reason=f"Action '{blocked_action}' requires human confirmation due to threat at checkpoint '{checkpoint}'.",
            status="PENDING",
        )
        _PENDING_APPROVALS[approval_id] = approval_req

    # Record to local audit jsonl
    try:
        os.makedirs("./data", exist_ok=True)
        with open("./data/audit_alerts.jsonl", "a", encoding="utf-8") as f:
            f.write(json.dumps(alert.model_dump(), default=str) + "\n")
    except Exception as exc:
        logger.warning("Could not persist alert to jsonl: %s", exc)

    # Fanout to Webhooks (Slack + Signed HTTP Webhook)
    _fanout_webhooks(alert, settings)

    return alert, approval_req


def _fanout_webhooks(alert: AlertEvent, settings) -> None:
    """Dispatches webhook payloads in best-effort mode."""
    payload = alert.model_dump()
    payload["timestamp"] = alert.timestamp.isoformat()

    # 1. Slack Incoming Webhook
    if settings.slack_webhook_url:
        try:
            slack_msg = {
                "text": (
                    f":warning: *AgentShield Security Alert [{alert.severity.value}]*\n"
                    f"*Checkpoint:* {alert.checkpoint}\n"
                    f"*Source Ref:* `{alert.source_ref}`\n"
                    f"*Blocked Action:* `{alert.blocked_action or 'None'}`\n"
                    f"*Evidence:* {'; '.join(alert.evidence) or 'None'}\n"
                    f"*Notice:* {alert.user_notice}"
                )
            }
            with httpx.Client(timeout=4.0) as client:
                client.post(settings.slack_webhook_url, json=slack_msg)
        except Exception as exc:
            logger.warning("Slack alert delivery failed: %s", exc)

    # 2. Automation Signed JSON Webhook (HMAC-SHA256)
    if settings.alert_webhook_url:
        try:
            raw_body = json.dumps(payload, default=str).encode('utf-8')
            headers = {"Content-Type": "application/json"}

            if settings.alert_webhook_secret:
                signature = hmac.new(
                    settings.alert_webhook_secret.encode('utf-8'),
                    raw_body,
                    hashlib.sha256,
                ).hexdigest()
                headers["X-AgentShield-Signature"] = f"sha256={signature}"

            with httpx.Client(timeout=4.0) as client:
                client.post(settings.alert_webhook_url, content=raw_body, headers=headers)
        except Exception as exc:
            logger.warning("Signed webhook alert delivery failed: %s", exc)


def get_all_alerts(limit: int = 50) -> List[AlertEvent]:
    return list(reversed(_ALERTS_LOG[-limit:]))


def get_pending_approvals() -> List[ApprovalRequest]:
    return [req for req in _PENDING_APPROVALS.values() if req.status == "PENDING"]


def resolve_approval(approval_id: str, decision: str) -> Optional[ApprovalRequest]:
    req = _PENDING_APPROVALS.get(approval_id)
    if not req:
        return None
    req.status = "APPROVED" if decision.upper() == "APPROVE" else "REJECTED"
    return req
