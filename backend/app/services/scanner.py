"""
AgentShield Layer 1: Fast Security Scanner
Deterministic heuristic pattern matching — no model required.
This layer runs first and is always available.
"""
from __future__ import annotations

import re
import time
from dataclasses import dataclass, field
from typing import List, Tuple

from app.schemas.models import ScannerFindings


# ─── Attack pattern catalogue ─────────────────────────────────────────────────
# Each entry: (pattern_name, regex, weight)
# Weight contributes to the raw_score (0–100 scale after normalization).

_PATTERNS: List[Tuple[str, re.Pattern, float]] = []


def _add(name: str, pattern: str, weight: float, flags: int = re.IGNORECASE) -> None:
    _PATTERNS.append((name, re.compile(pattern, flags), weight))


# Instruction-override attempts
_add("ignore_previous", r"ignore\s+(all\s+)?(previous|prior|above|earlier)\s+instructions?", 25)
_add("disregard_instructions", r"disregard\s+(all\s+)?(your\s+)?(instructions?|rules?|guidelines?)", 25)
_add("forget_instructions", r"forget\s+(everything|all|your)\s+(you\s+)?(know|were told|instructions?)", 20)
_add("new_instructions", r"(your\s+new|from\s+now\s+on|henceforth).{0,30}(instructions?|role|task|job)", 18)
_add("override_system", r"(override|bypass|circumvent)\s+(system|the\s+system|security|restrictions?)", 25)

# Secret / credential exfiltration
_add("reveal_secret", r"(reveal|show|print|output|disclose|display|expose)\s+(the\s+)?(secret|hidden|system\s+prompt|api\s+key|password|credentials?|config)", 30)
_add("what_is_system_prompt", r"(what\s+is|tell\s+me|show\s+me)\s+(your\s+)?(system\s+prompt|hidden\s+instructions?|initial\s+prompt)", 28)
_add("access_confidential", r"access\s+(confidential|sensitive|private|restricted)\s+(data|information|records?)", 22)

# Tool / action manipulation
_add("call_export", r"(call|invoke|execute|run|use)\s+(the\s+)?(export|send|transfer|upload|download)\s+(tool|function|api|action)", 22)
_add("send_to_external", r"send\s+(all|the|stored|user)?.{0,20}(records?|data|information|credentials?)\s+(to|via)\s+(external|remote|http|url|webhook)", 28)
_add("arbitrary_code", r"(execute|run|eval|exec)\s+(arbitrary|this|the\s+following)?\s*(code|script|command|shell|bash|python)", 30)

# Policy bypass attempts
_add("pretend_no_rules", r"(pretend|act\s+as\s+if|assume)\s+(you\s+)?(have\s+no\s+|there\s+are\s+no\s+|without\s+)(rules?|restrictions?|guidelines?|limitations?)", 22)
_add("developer_mode", r"(enable|activate|enter)\s+(developer|debug|god|unrestricted|jailbreak)\s+mode", 26)
_add("role_override", r"you\s+are\s+now\s+(a\s+)?(unrestricted|unfiltered|jailbroken|evil|hacked|different)", 24)
_add("jailbreak_dan", r"\b(DAN|JAILBREAK|DEVELOPER\s+MODE|SUDO|ROOT)\b", 26)

# Privilege escalation
_add("admin_access", r"(grant|give|elevate|escalate)\s+(me\s+)?(admin|root|superuser|elevated|full)\s+(access|privileges?|rights?|permissions?)", 24)
_add("authorized_user", r"(i\s+am|act\s+as\s+if\s+i\s+am)\s+(the\s+)?(admin|developer|owner|authorized|trusted)\s+(user|person|employee)", 20)

# SYSTEM tag injection
_add("system_tag_injection", r"(<\s*system\s*>|<\s*/\s*system\s*>|\[SYSTEM\]|\[\[SYSTEM\]\])", 28)
_add("instruction_injection_marker", r"(SYSTEM OVERRIDE|ADMIN OVERRIDE|ROOT COMMAND|OVERRIDE COMMAND)", 30)

# Synthetic secret canary pattern (for demo exfiltration scenarios)
_add("canary_secret", r"AGENTSHIELD-SECRET-\w+|canary_token_\w+|sk-demo-\w+", 15)


def scan(text: str) -> ScannerFindings:
    """
    Run all heuristic patterns against the input text.
    Returns ScannerFindings with matched patterns, indicators, and raw_score.
    """
    matched_names: List[str] = []
    matched_indicators: List[str] = []
    accumulated_score: float = 0.0

    for name, pattern, weight in _PATTERNS:
        match = pattern.search(text)
        if match:
            matched_names.append(name)
            matched_indicators.append(match.group(0)[:120])  # truncate for safety
            accumulated_score += weight

    # Cap raw_score at 100
    raw_score = min(accumulated_score, 100.0)

    return ScannerFindings(
        indicators_found=matched_indicators,
        patterns_matched=matched_names,
        raw_score=raw_score,
    )
