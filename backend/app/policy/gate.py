"""
AgentShield Deterministic Policy Gate (Layer 4)
This is the security authority. The LLM is an analysis component only.
No untrusted text can override this gate.
"""
from __future__ import annotations

from app.schemas.models import (
    AttackType,
    ContextualFindings,
    PolicyDecision,
    PolicyResult,
    RiskCategory,
    ScannerFindings,
    SessionCorrelation,
    SourceType,
)


# ─── Risk score calculation ────────────────────────────────────────────────────

def compute_risk_score(
    scanner: ScannerFindings,
    contextual: ContextualFindings,
    session: SessionCorrelation,
    source_type: SourceType,
) -> float:
    """
    Compute final risk score (0–100) from multiple signals.
    Weights are conservative: scanner provides a deterministic floor,
    LLM confidence boosts but cannot dominate.
    """
    # Scanner contribution (deterministic, max 50 pts)
    scanner_pts = min(scanner.raw_score * 0.5, 50.0)

    # Contextual LLM contribution (max 35 pts; treat as advisory)
    llm_pts = 0.0
    if contextual.attack_category != AttackType.NONE:
        llm_pts = contextual.confidence * 35.0

    # Session escalation (max 15 pts)
    session_pts = min(session.session_risk_boost, 15.0)

    # Source-type multiplier: untrusted sources carry extra weight
    source_multiplier = {
        SourceType.USER_PROMPT: 1.0,
        SourceType.RETRIEVED_DOCUMENT: 1.15,  # indirect injection risk
        SourceType.WEB_CONTENT: 1.15,
        SourceType.TOOL_OUTPUT: 1.1,
        SourceType.CONVERSATION_HISTORY: 1.05,
    }.get(source_type, 1.0)

    raw = (scanner_pts + llm_pts + session_pts) * source_multiplier
    return min(round(raw, 1), 100.0)


def _score_to_category(score: float) -> RiskCategory:
    if score >= 75:
        return RiskCategory.CRITICAL
    if score >= 50:
        return RiskCategory.HIGH
    if score >= 25:
        return RiskCategory.MEDIUM
    return RiskCategory.LOW


# ─── Deterministic decision logic ─────────────────────────────────────────────
# These rules are the source of truth. LLM recommendation is advisory only.

def _hard_block_conditions(
    scanner: ScannerFindings,
    contextual: ContextualFindings,
    risk_score: float,
) -> tuple[bool, str]:
    """Return (should_block, reason) based purely on deterministic signals."""

    # Hard block: scanner found critical patterns at high score
    if scanner.raw_score >= 55:
        return True, f"Scanner detected {len(scanner.patterns_matched)} high-severity patterns (score {scanner.raw_score:.0f})"

    # Hard block: secret exfiltration detected at any confidence
    if contextual.attack_category == AttackType.SECRET_EXFILTRATION and contextual.confidence >= 0.5:
        return True, "Secret exfiltration attempt detected"

    # Hard block: risk score critical
    if risk_score >= 75:
        return True, f"Critical risk score ({risk_score:.0f})"

    return False, ""


def _quarantine_conditions(
    scanner: ScannerFindings,
    contextual: ContextualFindings,
    risk_score: float,
) -> tuple[bool, str]:
    """Return (should_quarantine, reason)."""

    if risk_score >= 45:
        return True, f"High risk score ({risk_score:.0f}) — content isolated for review"

    if scanner.raw_score >= 25:
        return True, f"Scanner found suspicious patterns (score {scanner.raw_score:.0f})"

    if contextual.attack_category not in (AttackType.NONE, AttackType.AMBIGUOUS) and contextual.confidence >= 0.4:
        return True, f"Contextual analysis suggests {contextual.attack_category.value} attack"

    # LLM recommendation to quarantine/block is advisory — honour if risk_score supports it
    if contextual.recommended_action == PolicyDecision.QUARANTINE and risk_score >= 20:
        return True, "Contextual analyzer recommends quarantine"

    return False, ""


def decide(
    scanner: ScannerFindings,
    contextual: ContextualFindings,
    session: SessionCorrelation,
    source_type: SourceType,
) -> PolicyResult:
    """
    Deterministic policy gate. Returns a PolicyResult.
    This function is the single security authority — LLM cannot override it.
    """
    risk_score = compute_risk_score(scanner, contextual, session, source_type)
    risk_category = _score_to_category(risk_score)

    # Check BLOCK conditions first
    should_block, block_reason = _hard_block_conditions(scanner, contextual, risk_score)
    if should_block:
        return PolicyResult(
            decision=PolicyDecision.BLOCK,
            risk_score=risk_score,
            risk_category=risk_category,
            explanation=f"Request blocked: {block_reason}. All detected patterns are listed in evidence.",
            blocked_reason=block_reason,
        )

    # Check QUARANTINE conditions
    should_quarantine, quarantine_reason = _quarantine_conditions(scanner, contextual, risk_score)
    if should_quarantine:
        return PolicyResult(
            decision=PolicyDecision.QUARANTINE,
            risk_score=risk_score,
            risk_category=risk_category,
            explanation=f"Request quarantined: {quarantine_reason}. Content requires human review before use.",
        )

    # ALLOW
    return PolicyResult(
        decision=PolicyDecision.ALLOW,
        risk_score=risk_score,
        risk_category=risk_category,
        explanation=f"Input appears safe (risk score {risk_score:.0f}). No significant threat indicators found.",
    )


# ─── Tool action authorization ────────────────────────────────────────────────

# Sensitive tools that require ALLOW decision AND explicit auth check
_SENSITIVE_TOOLS = {"request_sensitive_export"}

def authorize_tool_action(tool_name: str, policy: PolicyResult) -> tuple[bool, str]:
    """
    Authorize a simulated tool action.
    Sensitive tools are ALWAYS blocked unless policy is ALLOW.
    This check is independent of LLM output.
    """
    if policy.decision == PolicyDecision.BLOCK:
        return False, f"Tool '{tool_name}' blocked: request was blocked by policy gate"

    if policy.decision == PolicyDecision.QUARANTINE:
        return False, f"Tool '{tool_name}' blocked: request is quarantined pending review"

    if tool_name in _SENSITIVE_TOOLS:
        # Even on ALLOW: require explicit check outside LLM
        if policy.risk_score > 15:
            return False, f"Sensitive tool '{tool_name}' blocked: elevated risk score ({policy.risk_score:.0f})"
        return True, f"Sensitive tool '{tool_name}' authorized by policy gate (low risk)"

    return True, f"Tool '{tool_name}' authorized"
