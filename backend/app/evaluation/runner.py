"""
AgentShield Evaluation Engine
Runs the labeled dataset through the security pipeline and computes metrics.
"""
from __future__ import annotations

import json
import os
import statistics
import uuid
from collections import defaultdict
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple

from app.schemas.models import (
    AnalyzeRequest,
    CategoryMetrics,
    EvaluationResult,
    ExecutionMode,
    PolicyDecision,
    SourceType,
)
from app.graph.workflow import run_security_pipeline
from app.core.config import get_settings
from app.storage.database import save_evaluation_result

import logging

logger = logging.getLogger(__name__)

_DEFAULT_DATASET_PATH = os.path.join(
    os.path.dirname(__file__), "..", "..", "data", "evaluation_dataset.json"
)


def _load_dataset(path: Optional[str] = None, max_examples: Optional[int] = None) -> List[dict]:
    target = os.path.abspath(path or _DEFAULT_DATASET_PATH)
    with open(target, "r", encoding="utf-8") as f:
        data = json.load(f)
    if max_examples:
        data = data[:max_examples]
    return data


async def run_evaluation(
    dataset_path: Optional[str] = None,
    max_examples: Optional[int] = None,
) -> EvaluationResult:
    """
    Run the full evaluation pipeline over the labeled dataset.
    Returns computed metrics — never fabricated.
    """
    dataset = _load_dataset(dataset_path, max_examples)
    settings = get_settings()

    true_positives = 0
    false_positives = 0
    false_negatives = 0
    true_negatives = 0
    dangerous_blocked = 0
    dangerous_total = 0
    latencies: List[float] = []

    # Category-level tracking: {category: {label: count}}
    cat_results: Dict[str, Dict[str, int]] = defaultdict(lambda: defaultdict(int))
    # Confusion matrix: {expected: {actual: count}}
    confusion: Dict[str, Dict[str, int]] = defaultdict(lambda: defaultdict(int))

    import time

    for example in dataset:
        example_id = example.get("id", "?")
        text = example["text"]
        source_type_str = example.get("source_type", "user_prompt")
        label = example["label"]  # "benign", "benign_security_discussion", "attack"
        expected_decision = example.get("expected_decision", "ALLOW")
        category = example.get("category", "unknown")

        try:
            source_type = SourceType(source_type_str)
        except ValueError:
            source_type = SourceType.USER_PROMPT

        req = AnalyzeRequest(text=text, source_type=source_type)

        t0 = time.monotonic()
        try:
            state = await run_security_pipeline(req)
            actual_decision = state.policy_result.decision.value if state.policy_result else "ALLOW"
        except Exception as exc:
            logger.warning("Eval example %s failed: %s", example_id, exc)
            actual_decision = "ALLOW"

        latency = (time.monotonic() - t0) * 1000
        latencies.append(latency)

        # Build confusion
        confusion[expected_decision][actual_decision] += 1
        cat_results[category][f"{expected_decision}_{actual_decision}"] += 1

        # Compute TP/FP/FN/TN
        is_attack = label == "attack"
        is_blocked = actual_decision in ("BLOCK", "QUARANTINE")

        if is_attack and is_blocked:
            true_positives += 1
        elif is_attack and not is_blocked:
            false_negatives += 1
        elif not is_attack and is_blocked:
            false_positives += 1
        else:
            true_negatives += 1

        # Track dangerous action blocking
        if is_attack:
            dangerous_total += 1
            if actual_decision == "BLOCK":
                dangerous_blocked += 1

    # Compute metrics
    total = len(dataset)
    recall = true_positives / max(true_positives + false_negatives, 1)
    precision = true_positives / max(true_positives + false_positives, 1)
    fp_rate = false_positives / max(false_positives + true_negatives, 1)
    block_rate = dangerous_blocked / max(dangerous_total, 1)

    median_latency = statistics.median(latencies) if latencies else None

    # Build category metrics
    category_metrics = []
    all_cats = set(cat_results.keys())
    for cat in sorted(all_cats):
        cat_data = cat_results[cat]
        cat_total = sum(cat_data.values())
        # correct = expected matches actual
        cat_correct = cat_data.get("ALLOW_ALLOW", 0) + cat_data.get("BLOCK_BLOCK", 0) + cat_data.get("QUARANTINE_QUARANTINE", 0)
        category_metrics.append(
            CategoryMetrics(label=cat, total=cat_total, correct=cat_correct)
        )

    exec_mode = ExecutionMode.FULL if settings.groq_configured else ExecutionMode.LOCAL_BASELINE

    result = EvaluationResult(
        run_id=str(uuid.uuid4()),
        timestamp=datetime.now(timezone.utc),
        total_examples=total,
        attack_recall=round(recall, 3),
        precision=round(precision, 3),
        false_positive_rate=round(fp_rate, 3),
        block_rate_on_dangerous=round(block_rate, 3),
        median_latency_ms=round(median_latency, 1) if median_latency else None,
        category_metrics=category_metrics,
        confusion_matrix={k: dict(v) for k, v in confusion.items()},
        execution_mode=exec_mode,
        notes=(
            "Groq LLM was used for contextual analysis."
            if settings.groq_configured
            else "Local heuristic baseline used (Groq not configured). "
               "Results reflect deterministic scanner only. "
               "Detection is probabilistic — this is not a certified security product."
        ),
    )

    # Persist
    save_evaluation_result(result)
    return result
