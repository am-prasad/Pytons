"""
AgentShield Session Risk Correlator & Crescendo Detector
Tracks per-session risk history and multi-turn reconnaissance crescendo:
- Bounded history per session
- Session isolation to prevent cross-tenant state leakage
- Probing signal tracking:
    1. Tool / capability discovery
    2. Internal rule / guideline inquiry
    3. Verbatim repetition / extraction
- Escalation triggered when cumulative probing signals cross threshold,
  even if individual turns appear low-risk.
"""
from __future__ import annotations

import re
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Deque, Dict, List, Optional, Set

from app.schemas.models import PolicyDecision, SessionCorrelation

MAX_SESSION_HISTORY = 20    # Bounded per-session event count
MAX_ACTIVE_SESSIONS = 1000  # Evict oldest when capacity exceeded

# Heuristic patterns for probing reconnaissance
PROBE_TOOLS = re.compile(r'(what|which|list|show|have).{0,30}(tools?|functions?|apis?|actions?|capabilities)', re.IGNORECASE)
PROBE_RULES = re.compile(r'(what|tell me|show me|explain|your).{0,30}(rules?|instructions?|guidelines?|system prompt|constraints)', re.IGNORECASE)
PROBE_EXTRACT = re.compile(r'(repeat|print|output|recite|reveal|show).{0,30}(verbatim|exact|word for word|them all|everything)', re.IGNORECASE)


@dataclass
class _SessionEvent:
    timestamp: float
    risk_score: float
    decision: PolicyDecision
    attack_types: List[str]
    request_id: str
    text_snippet: str = ""
    probes_detected: Set[str] = field(default_factory=set)


class SessionStore:
    """In-memory session store providing bounded history and tenant isolation."""

    def __init__(self) -> None:
        self._sessions: Dict[str, Deque[_SessionEvent]] = defaultdict(
            lambda: deque(maxlen=MAX_SESSION_HISTORY)
        )
        self._creation_order: Deque[str] = deque(maxlen=MAX_ACTIVE_SESSIONS)

    def _ensure_capacity(self, session_id: str) -> None:
        if session_id not in self._sessions:
            if len(self._creation_order) >= MAX_ACTIVE_SESSIONS:
                oldest = self._creation_order[0]
                self._sessions.pop(oldest, None)
            self._creation_order.append(session_id)

    def inspect_text_probes(self, text: str) -> Set[str]:
        """Detects whether this turn contains probing reconnaissance signals."""
        probes = set()
        if PROBE_TOOLS.search(text):
            probes.add("tool_probing")
        if PROBE_RULES.search(text):
            probes.add("rule_probing")
        if PROBE_EXTRACT.search(text):
            probes.add("verbatim_extraction_probing")
        return probes

    def add_event(
        self,
        session_id: str,
        risk_score: float,
        decision: PolicyDecision,
        attack_types: List[str],
        request_id: str,
        text: str = "",
    ) -> None:
        self._ensure_capacity(session_id)
        probes = self.inspect_text_probes(text)
        self._sessions[session_id].append(
            _SessionEvent(
                timestamp=time.time(),
                risk_score=risk_score,
                decision=decision,
                attack_types=attack_types,
                request_id=request_id,
                text_snippet=text[:100],
                probes_detected=probes,
            )
        )

    def get_correlation(self, session_id: Optional[str], incoming_text: str = "") -> SessionCorrelation:
        """
        Computes session correlation and crescendo drift detection for incoming request.
        """
        if not session_id:
            return SessionCorrelation()

        events = list(self._sessions.get(session_id, deque()))
        if not events and not incoming_text:
            return SessionCorrelation(session_id=session_id)

        # 1. Tally historical probing signals
        historical_probes: Set[str] = set()
        for e in events:
            historical_probes.update(e.probes_detected)

        # 2. Check incoming text probes
        incoming_probes = self.inspect_text_probes(incoming_text)
        total_unique_probes = historical_probes.union(incoming_probes)
        probing_count = len(total_unique_probes)

        # 3. Prior risky events
        prior_risk_events = sum(
            1 for e in events if e.decision in (PolicyDecision.QUARANTINE, PolicyDecision.BLOCK)
        )

        # 4. Crescendo Detection:
        # If user has queried tools, then queried rules, and now asks for verbatim extraction -> crescendo!
        crescendo_detected = False
        crescendo_reason = None

        if len(events) >= 2:
            has_tool_probe = "tool_probing" in total_unique_probes
            has_rule_probe = "rule_probing" in total_unique_probes
            has_extract_probe = "verbatim_extraction_probing" in incoming_probes or "verbatim_extraction_probing" in total_unique_probes

            if has_tool_probe and has_rule_probe and has_extract_probe:
                crescendo_detected = True
                crescendo_reason = (
                    "Multi-turn reconnaissance crescendo detected: cumulative probing sequence "
                    "(capabilities -> internal rules -> verbatim repetition)."
                )

        # Also trigger if 2 or more prior turns were quarantined/blocked
        if not crescendo_detected and prior_risk_events >= 2:
            scores = [e.risk_score for e in events]
            if len(scores) >= 2 and scores[-1] >= scores[0]:
                crescendo_detected = True
                crescendo_reason = f"Multi-turn escalation detected across {prior_risk_events} prior suspicious turns."

        # Risk boost
        boost = min(prior_risk_events * 5.0 + probing_count * 4.0, 15.0)
        contributing = [e.request_id for e in events if e.decision != PolicyDecision.ALLOW or e.probes_detected]

        return SessionCorrelation(
            session_id=session_id,
            prior_risk_events=prior_risk_events,
            probing_count=probing_count,
            escalation_detected=crescendo_detected,
            session_risk_boost=boost,
            contributing_events=contributing[-5:],
            crescendo_reason=crescendo_reason,
        )

    def reset(self, session_id: str) -> bool:
        """Clear session state. Returns True if session existed."""
        existed = session_id in self._sessions
        self._sessions.pop(session_id, None)
        try:
            self._creation_order.remove(session_id)
        except ValueError:
            pass
        return existed


# Module-level singleton store
_store = SessionStore()


def get_store() -> SessionStore:
    return _store
