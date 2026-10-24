"""
AgentShield Deterministic Policy Gate (Layer 4)
This is the supreme security authority.
The LLM is strictly an analysis component.
No untrusted text or model output can grant permission to execute actions.

Implements:
- Mathematical multi-signal risk scoring
- Decision semantics: ALLOW, QUARANTINE, BLOCK, REQUIRE_APPROVAL
- Strict tool allowlist enforcement
- Egress exfiltration controls (recipient domain validation)
- Human approval gating for sensitive actions under elevated risk
"""
from __future__ import annotations

import re
from typing import Any, Dict, Optional, Set, Tuple

from app.core.config import get_settings
from app.schemas.models import (
    ALLOWED_TOOL_NAMES,
    AttackType,
    ContextualFindings,
    PolicyDecision,
    PolicyResult,
    RiskCategory,
    ScannerFindings,
    SessionCorrelation,
    SourceType,
)

# Sensitive actions that carry data exfiltration or state mutation risk
_SENSITIVE_TOOLS: Set[str] = {"send_email", "request_sensitive_export"}

EMAIL_REGEX = re.compile(r'[\w\.-]+@([\w\.-]+\.\w+)')


def compute_risk_score(
    scanner: ScannerFindings,
    contextual: ContextualFindings,
    session: SessionCorrelation,
    source_type: SourceType,
) -> float:
    """
    Computes final risk score (0–100) from independent security layers.
    Scanner provides deterministic floor; LLM adds advisory nuance;
    session history catches slow crescendo drift.
    """
    settings = get_settings()

    # Layer 1: Scanner contribution (deterministic, max 50 pts)
    scanner_pts = min(scanner.raw_score * 0.5, 50.0)

    # Layer 2: Contextual LLM contribution (advisory, max 35 pts)
    llm_pts = 0.0
    if contextual.attack_category not in (AttackType.NONE, AttackType.AMBIGUOUS):
        llm_pts = contextual.confidence * 35.0

    # Layer 3: Multi-turn session escalation (max 15 pts)
    session_pts = min(session.session_risk_boost, 15.0)

    # Source-type multiplier: untrusted retrieval/web carries elevated risk
    source_multiplier = {
        SourceType.USER_PROMPT: 1.0,
        SourceType.RETRIEVED_DOCUMENT: 1.15,
        SourceType.WEB_CONTENT: 1.15,
        SourceType.TOOL_OUTPUT: 1.10,
        SourceType.CONVERSATION_HISTORY: 1.05,
    }.get(source_type, 1.0)

    raw = (scanner_pts + llm_pts + session_pts) * source_multiplier
    return min(round(raw, 1), 100.0)


def _score_to_category(score: float) -> RiskCategory:
    settings = get_settings()
    if score >= settings.risk_threshold_block:
        return RiskCategory.CRITICAL
    if score >= 50.0:
        return RiskCategory.HIGH
    if score >= settings.risk_threshold_quarantine:
        return RiskCategory.MEDIUM
    return RiskCategory.LOW


def decide(
    scanner: ScannerFindings,
    contextual: ContextualFindings,
    session: SessionCorrelation,
    source_type: SourceType,
) -> PolicyResult:
    """
    Evaluates all signals through the deterministic policy matrix.
    LLM cannot override hard security rules.
    """
    settings = get_settings()
    risk_score = compute_risk_score(scanner, contextual, session, source_type)
    risk_category = _score_to_category(risk_score)

    # 1. Hard Block: Scanner detected unambiguous high-severity injection
    if scanner.raw_score >= 55.0:
        reason = f"Deterministic scanner matched high-severity patterns (score {scanner.raw_score:.0f})"
        return PolicyResult(
            decision=PolicyDecision.BLOCK,
            risk_score=risk_score,
            risk_category=risk_category,
            explanation=f"Execution blocked: {reason}.",
            blocked_reason=reason,
        )

    # 2. Hard Block: Secret exfiltration attempt
    if contextual.attack_category == AttackType.SECRET_EXFILTRATION and contextual.confidence >= 0.5:
        reason = "Targeted secret / credential exfiltration attempt detected"
        return PolicyResult(
            decision=PolicyDecision.BLOCK,
            risk_score=risk_score,
            risk_category=risk_category,
            explanation=f"Execution blocked: {reason}.",
            blocked_reason=reason,
        )

    # 3. Hard Block: Multi-turn crescendo policy violation
    if session.escalation_detected:
        reason = session.crescendo_reason or "Multi-turn probing and risk crescendo threshold exceeded"
        return PolicyResult(
            decision=PolicyDecision.BLOCK,
            risk_score=max(risk_score, 80.0),
            risk_category=RiskCategory.CRITICAL,
            explanation=f"Execution blocked by session correlation: {reason}.",
            blocked_reason=reason,
        )

    # 4. Critical score threshold
    if risk_score >= settings.risk_threshold_block:
        reason = f"Aggregated risk score exceeded block threshold ({risk_score:.0f} >= {settings.risk_threshold_block})"
        return PolicyResult(
            decision=PolicyDecision.BLOCK,
            risk_score=risk_score,
            risk_category=risk_category,
            explanation=f"Execution blocked: {reason}.",
            blocked_reason=reason,
        )

    # 5. Quarantine: Ambiguous or moderate risk
    if risk_score >= settings.risk_threshold_quarantine or scanner.raw_score >= settings.scanner_suspicious_threshold:
        reason = f"Elevated threat indicators present (score {risk_score:.0f})"
        return PolicyResult(
            decision=PolicyDecision.QUARANTINE,
            risk_score=risk_score,
            risk_category=risk_category,
            explanation=f"Quarantined for review: {reason}. Content isolated from privileged operations.",
        )

    # 6. Safe: Allow
    return PolicyResult(
        decision=PolicyDecision.ALLOW,
        risk_score=risk_score,
        risk_category=risk_category,
        explanation=f"Content verified safe (risk score {risk_score:.0f}). No hostile patterns detected.",
    )


# ─── Tool Authorization & Egress Rule ──────────────────────────────────────────

def authorize_tool_action(
    tool_name: str,
    parameters: Dict[str, Any],
    policy: PolicyResult,
    user_task: str = "",
) -> Tuple[PolicyDecision, str]:
    """
    Strict action boundary authorization.
    Verifies allowlist, egress recipient domains, and human approval gates.
    """
    settings = get_settings()

    # Rule 1: Allowlist validation
    if tool_name not in ALLOWED_TOOL_NAMES:
        return (
            PolicyDecision.BLOCK,
            f"Unauthorized action: '{tool_name}' is not in the allowed tool registry.",
        )

    # Rule 2: Non-negotiable block if request was blocked by policy gate
    if policy.decision == PolicyDecision.BLOCK:
        return (
            PolicyDecision.BLOCK,
            f"Action '{tool_name}' denied: workflow was blocked by policy gate ({policy.blocked_reason or 'high risk'}).",
        )

    # Rule 3: Safe, non-sensitive read-only tools
    if tool_name not in _SENSITIVE_TOOLS:
        return PolicyDecision.ALLOW, f"Tool '{tool_name}' authorized (read-only safe tool)."

    # Rule 4: Egress Control for send_email
    if tool_name == "send_email":
        recipient = str(parameters.get("to", "")).strip().lower()
        if not recipient:
            return PolicyDecision.BLOCK, "Action 'send_email' denied: missing recipient address."

        # Extract domain
        domain_match = EMAIL_REGEX.search(recipient)
        domain = domain_match.group(1).lower() if domain_match else ""

        # Egress check: Allowed if user message explicitly specifies recipient OR domain is whitelisted
        user_mentions_recipient = recipient in user_task.lower()
        domain_allowed = domain in settings.outbound_allowed_domains_list

        if not (user_mentions_recipient or domain_allowed):
            return (
                PolicyDecision.BLOCK,
                f"Egress rule violation: recipient '{recipient}' (domain: '{domain}') is not in "
                f"OUTBOUND_ALLOWED_DOMAINS and was not specified by the user. Action blocked as exfiltration.",
            )

    # Rule 5: Threat detected in same request -> Require Approval
    if policy.risk_score >= settings.risk_threshold_quarantine or policy.decision == PolicyDecision.QUARANTINE:
        return (
            PolicyDecision.REQUIRE_APPROVAL,
            f"Action '{tool_name}' requires human approval due to elevated document threat score ({policy.risk_score:.0f}).",
        )

    # Rule 6: Sensitive tool allowed on verified low risk
    if policy.risk_score <= 15.0:
        return PolicyDecision.ALLOW, f"Sensitive action '{tool_name}' authorized by policy gate."

    return (
        PolicyDecision.REQUIRE_APPROVAL,
        f"Sensitive action '{tool_name}' held for human confirmation (risk score {policy.risk_score:.0f}).",
    )
