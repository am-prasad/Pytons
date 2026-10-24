"""
AgentShield Session Risk Correlator
Tracks per-session risk history to detect multi-turn attacks.
Uses in-memory store bounded by session count and event count.
Session isolation prevents cross-user state leakage.
"""
from __future__ import annotations

import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Deque, Dict, List, Optional

from app.schemas.models import PolicyDecision, SessionCorrelation

# ─── Session state ─────────────────────────────────────────────────────────────
MAX_SESSION_HISTORY = 20    # bounded per-session event count
MAX_ACTIVE_SESSIONS = 1000  # evict oldest when exceeded


@dataclass
class _SessionEvent:
    timestamp: float
    risk_score: float
    decision: PolicyDecision
    attack_types: List[str]
    request_id: str


class SessionStore:
    """In-memory session risk store. Thread-safe via GIL for single-process use."""

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

    def add_event(
        self,
        session_id: str,
        risk_score: float,
        decision: PolicyDecision,
        attack_types: List[str],
        request_id: str,
    ) -> None:
        self._ensure_capacity(session_id)
        self._sessions[session_id].append(
            _SessionEvent(
                timestamp=time.time(),
                risk_score=risk_score,
                decision=decision,
                attack_types=attack_types,
                request_id=request_id,
            )
        )

    def get_correlation(self, session_id: Optional[str]) -> SessionCorrelation:
        """Compute session correlation for the given session ID."""
        if not session_id:
            return SessionCorrelation()

        events = list(self._sessions.get(session_id, deque()))
        if not events:
            return SessionCorrelation(session_id=session_id)

        prior_risk_events = sum(
            1 for e in events if e.decision in (PolicyDecision.QUARANTINE, PolicyDecision.BLOCK)
        )

        # Detect escalation: increasing risk_score trend
        scores = [e.risk_score for e in events]
        escalation = len(scores) >= 3 and scores[-1] > scores[0] and prior_risk_events >= 2

        # Boost based on prior risky events (max +15)
        boost = min(prior_risk_events * 5.0, 15.0)

        contributing = [e.request_id for e in events if e.decision != PolicyDecision.ALLOW]

        return SessionCorrelation(
            session_id=session_id,
            prior_risk_events=prior_risk_events,
            escalation_detected=escalation,
            session_risk_boost=boost,
            contributing_events=contributing[-5:],  # last 5 risky events
        )

    def reset(self, session_id: str) -> bool:
        """Clear session history. Returns True if session existed."""
        existed = session_id in self._sessions
        self._sessions.pop(session_id, None)
        try:
            self._creation_order.remove(session_id)
        except ValueError:
            pass
        return existed


# ─── Global session store (module-level singleton) ────────────────────────────
# Session isolation: each session_id maps to its own bounded deque.
_store = SessionStore()


def get_store() -> SessionStore:
    return _store
