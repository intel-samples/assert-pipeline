# Copyright (C) 2026 Intel Corporation
# SPDX-License-Identifier: MIT
"""Shared helpers for extracting LLM cost metrics.

Centralises the best-effort cost extraction logic that was previously
duplicated across the pipeline stage modules (intro, analyzer, evaluator,
extractor).
"""

from typing import Any


def extract_conversation_cost_metrics(conversation: Any) -> dict[str, Any]:
    """Best-effort extraction of cost metrics from OpenHands conversation stats."""
    result: dict[str, Any] = {
        "total_cost": None,
        "per_usage_cost": {},
    }

    stats = getattr(conversation, "conversation_stats", None)
    if stats is None:
        return result

    combined_metrics_getter = getattr(stats, "get_combined_metrics", None)
    if callable(combined_metrics_getter):
        combined = combined_metrics_getter()
        result["total_cost"] = getattr(combined, "accumulated_cost", None)

    usage_to_metrics = getattr(stats, "usage_to_metrics", None)
    if isinstance(usage_to_metrics, dict):
        result["per_usage_cost"] = {
            usage_id: getattr(metrics, "accumulated_cost", None)
            for usage_id, metrics in usage_to_metrics.items()
        }

    return result


def extract_completion_cost_metrics(metrics: Any) -> dict[str, Any]:
    """Best-effort extraction of completion cost metrics for a single LLM call."""
    result: dict[str, Any] = {
        "total_cost": None,
        "per_usage_cost": {},
    }

    # Preferred direct metric shape (when exposed by SDK wrappers).
    direct_cost = getattr(metrics, "accumulated_cost", None)
    if direct_cost is not None:
        result["total_cost"] = direct_cost
        result["per_usage_cost"] = {"main": direct_cost}

    return result
