"""
AgentShield Safe Simulated Tools
These tools use dummy data only. No real actions, transactions, or external calls.
The policy gate must authorize each tool before it executes.
"""
from __future__ import annotations

import random
import time
from typing import Any, Dict

# ─── Dummy data (no real credentials or sensitive data) ───────────────────────

_PUBLIC_STATUSES = [
    {"status": "operational", "uptime": "99.97%", "region": "us-east-1"},
    {"status": "degraded", "uptime": "98.12%", "region": "eu-west-2"},
    {"status": "operational", "uptime": "99.99%", "region": "ap-south-1"},
]

_DEMO_DOCUMENTS = [
    {
        "id": "doc-001",
        "title": "Cloud Security Best Practices",
        "excerpt": "Encrypt data at rest and in transit. Use IAM roles with least privilege...",
        "score": 0.91,
    },
    {
        "id": "doc-002",
        "title": "Prompt Injection Defenses",
        "excerpt": "Separate application instructions from user input. Validate all LLM output...",
        "score": 0.87,
    },
    {
        "id": "doc-003",
        "title": "Zero Trust Architecture",
        "excerpt": "Never trust, always verify. Apply micro-segmentation to workloads...",
        "score": 0.82,
    },
]

# Synthetic canary — never real credentials
_CANARY_SECRET = "AGENTSHIELD-SECRET-DEMO-NOT-REAL-DATA"


def get_public_status(parameters: Dict[str, Any]) -> Dict[str, Any]:
    """Returns a dummy system status. Safe to call without authorization."""
    region = parameters.get("region", "any")
    status = random.choice(_PUBLIC_STATUSES)
    return {
        "tool": "get_public_status",
        "region_requested": region,
        "result": status,
        "note": "Simulated demo data only.",
    }


def search_demo_documents(parameters: Dict[str, Any]) -> Dict[str, Any]:
    """Returns dummy document search results. Safe to call without authorization."""
    query = str(parameters.get("query", ""))[:100]
    return {
        "tool": "search_demo_documents",
        "query": query,
        "results": _DEMO_DOCUMENTS[:2],
        "note": "Simulated demo documents only.",
    }


def request_sensitive_export(parameters: Dict[str, Any]) -> Dict[str, Any]:
    """
    Sensitive simulated export tool.
    MUST be authorized by the independent policy gate before this code runs.
    Returns a harmless simulated result — never performs real export.
    The canary secret is a dummy value used only to test detection.
    """
    destination = str(parameters.get("destination", "unspecified"))[:50]
    return {
        "tool": "request_sensitive_export",
        "destination": destination,
        "result": "SIMULATED: Export job queued. No real data was transferred.",
        "canary": _CANARY_SECRET,
        "note": "This is a demonstration only. No actual export occurred.",
    }


# ─── Tool dispatcher (allowlist enforced) ─────────────────────────────────────

_TOOL_REGISTRY: Dict[str, Any] = {
    "get_public_status": get_public_status,
    "search_demo_documents": search_demo_documents,
    "request_sensitive_export": request_sensitive_export,
}


def execute_tool(tool_name: str, parameters: Dict[str, Any]) -> Dict[str, Any]:
    """
    Execute a simulated tool by name.
    Tool name MUST already have been validated against the allowlist before calling this.
    Parameters are passed through as-is (all tools use dummy data only).
    """
    fn = _TOOL_REGISTRY.get(tool_name)
    if fn is None:
        # Should not reach here if allowlist check passed in schema validation
        raise ValueError(f"Tool '{tool_name}' not found in registry")
    return fn(parameters)
