# Copyright (C) 2026 Intel Corporation
# SPDX-License-Identifier: MIT
"""
Security Analysis Pipeline for Repositories.

Uses LangGraph's StateGraph for prompt-chaining orchestration.
Each node wraps an existing analysis step (using openhands.sdk internally)
and passes its output forward through shared state, forming a sequential
chain that future security-analysis nodes can extend.
"""

import argparse
from datetime import datetime
import json
import os
from pathlib import Path
import re
import sys
from typing import Any, TypedDict

from langgraph.graph import END, START, StateGraph
import litellm
from litellm.utils import register_model

from config.preset_config import ResolvedPreset, list_presets, load_preset

# Ensure the packages are importable
sys.path.insert(0, "intro")
sys.path.insert(0, "analyzer")
sys.path.insert(0, "evaluator")
sys.path.insert(0, "extractor")

from intro.introduction import identify_review_areas
from analyzer.analysis import analyze_repo_security
from evaluator.evaluation import evaluate_vulnerabilities
from extractor.extraction import extract_confirmed_issues, ConfirmedIssuesReport

# ---------------------------------------------------------------------------
# Model pricing overrides
# ---------------------------------------------------------------------------
_MODEL_PRICES_OVERRIDE_FILENAME = "model_prices.local.json"


def apply_model_price_overrides() -> None:
    """Layer optional user pricing on top of LiteLLM's fresh cost map.

    LiteLLM fetches the base map from ``LITELLM_MODEL_COST_MAP_URL`` (upstream
    GitHub by default); this merges any local additions/corrections via
    ``register_model`` so users needn't edit the upstream file.
    """
    candidates = [
        Path(os.getenv("MODEL_PRICES_OVERRIDE_PATH", "")),
        Path(__file__).resolve().parent / _MODEL_PRICES_OVERRIDE_FILENAME,
    ]
    path = next((p for p in candidates if p and p.is_file()), None)
    if path is None:
        return
    try:
        with open(path) as fh:
            overrides = json.load(fh)
    except (OSError, json.JSONDecodeError) as exc:
        print(f"Warning: skipping model price overrides from {path}: {exc}")
        return
    if isinstance(overrides, dict) and overrides:
        specs = {k: v for k, v in overrides.items() if isinstance(v, dict)}
        if specs:
            register_model(specs)
            print(f"Applied {len(specs)} model price override(s) from {path}")


# ---------------------------------------------------------------------------
# Timing utilities
# ---------------------------------------------------------------------------
def format_elapsed_time(start: datetime, end: datetime) -> str:
    """Format elapsed time between two datetime objects."""
    elapsed = end - start
    hours, remainder = divmod(elapsed.total_seconds(), 3600)
    minutes, seconds = divmod(remainder, 60)
    
    if hours > 0:
        return f"{int(hours)}h {int(minutes)}m {seconds:.1f}s"
    elif minutes > 0:
        return f"{int(minutes)}m {seconds:.1f}s"
    else:
        return f"{seconds:.1f}s"


def format_cost(cost: Any) -> str:
    """Format monetary cost for logs."""
    if cost is None:
        return "unavailable"
    try:
        return f"${float(cost):.6f}"
    except (TypeError, ValueError):
        return "unavailable"


def merge_stage_costs(
    stage_costs: dict[str, dict[str, Any]],
    stage_name: str,
    metrics: dict[str, Any],
) -> dict[str, dict[str, Any]]:
    """Return a copy with one stage's cost metrics added/updated."""
    merged = dict(stage_costs)
    merged[stage_name] = {
        "total_cost": metrics.get("total_cost"),
        "per_usage_cost": metrics.get("per_usage_cost", {}),
    }
    return merged


def print_stage_cost_summary(stage_name: str, metrics: dict[str, Any]) -> None:
    """Print concise per-stage money utilization summary."""
    print(f"[{stage_name}] Cost total: {format_cost(metrics.get('total_cost'))}")
    per_usage = metrics.get("per_usage_cost", {})
    if not isinstance(per_usage, dict) or not per_usage:
        print(f"[{stage_name}] Cost by usage: unavailable")
        return
    for usage_id, usage_cost in per_usage.items():
        print(f"[{stage_name}] Cost by usage ({usage_id}): {format_cost(usage_cost)}")


def compute_overall_cost(stage_costs: dict[str, dict[str, Any]]) -> float | None:
    """Compute total known cost across stages when available."""
    known_costs: list[float] = []
    for stage_data in stage_costs.values():
        total_cost = stage_data.get("total_cost")
        if total_cost is None:
            continue
        try:
            known_costs.append(float(total_cost))
        except (TypeError, ValueError):
            continue
    if not known_costs:
        return None
    return sum(known_costs)


# ---------------------------------------------------------------------------
# State schema – every node reads from / writes to this shared dict.
# Add new keys here as you introduce additional analysis steps.
# ---------------------------------------------------------------------------
class AnalysisState(TypedDict):
    repo_path: str
    user_focus: str  # Optional brief suggestion about important code areas
    preset: ResolvedPreset  # Resolved model preset from model_presets.json
    output_dir: str  # Per-run directory where all step reports are saved
    # Outputs produced by pipeline nodes (populated during execution)
    review_areas_path: str
    vulnerability_report_path: str
    confirmed_vulnerabilities_path: str
    confirmed_issues: ConfirmedIssuesReport | None
    # Timing information for each stage
    introduction_start_time: datetime | None
    introduction_end_time: datetime | None
    analysis_start_time: datetime | None
    analysis_end_time: datetime | None
    evaluation_start_time: datetime | None
    evaluation_end_time: datetime | None
    extraction_start_time: datetime | None
    extraction_end_time: datetime | None
    # Cost information for each stage and accumulated known total
    stage_costs: dict[str, dict[str, Any]]
    known_total_cost: float | None

# ---------------------------------------------------------------------------
# Node functions
# Each node receives the full state dict and returns a partial update.
# The actual LLM interaction happens inside the called function (using openhands.sdk).
# ---------------------------------------------------------------------------
def introduction_node(state: AnalysisState) -> dict:
    """Traverse the repository and identify security-relevant review areas."""
    start_time = datetime.now()
    print(f"\n[INTRODUCTION] Stage started at: {start_time.strftime('%Y-%m-%d %H:%M:%S')}")
    
    preset = state["preset"]
    output_path = os.path.join(state["output_dir"], "review_areas.md")
    path, cost_metrics = identify_review_areas(
        state["repo_path"],
        output_path=output_path,
        user_focus=state["user_focus"],
        model_config=preset.intro,
        retry_config=preset.retry,
    )
    
    end_time = datetime.now()
    elapsed = format_elapsed_time(start_time, end_time)
    print(f"[INTRODUCTION] Stage completed at: {end_time.strftime('%Y-%m-%d %H:%M:%S')} (elapsed: {elapsed})")
    print_stage_cost_summary("INTRODUCTION", cost_metrics)

    stage_costs = merge_stage_costs(state["stage_costs"], "introduction", cost_metrics)
    known_total_cost = compute_overall_cost(stage_costs)
    
    return {
        "review_areas_path": path,
        "introduction_start_time": start_time,
        "introduction_end_time": end_time,
        "stage_costs": stage_costs,
        "known_total_cost": known_total_cost,
    }


def security_analysis_node(state: AnalysisState) -> dict:
    """Run CWE-classified security analysis on the identified review areas."""
    start_time = datetime.now()
    print(f"\n[ANALYSIS] Stage started at: {start_time.strftime('%Y-%m-%d %H:%M:%S')}")
    
    preset = state["preset"]
    output_path = os.path.join(state["output_dir"], "vulnerability_report.md")
    artifacts_dir = os.path.join(state["output_dir"], "analysis_artifacts")
    path, cost_metrics = analyze_repo_security(
        state["repo_path"],
        review_areas_path=state["review_areas_path"],
        output_path=output_path,
        artifacts_dir=artifacts_dir,
        model_config=preset.analysis,
        subagent_model_config=preset.subagent_analysis,
        retry_config=preset.retry,
    )
    
    end_time = datetime.now()
    elapsed = format_elapsed_time(start_time, end_time)
    print(f"[ANALYSIS] Stage completed at: {end_time.strftime('%Y-%m-%d %H:%M:%S')} (elapsed: {elapsed})")
    print_stage_cost_summary("ANALYSIS", cost_metrics)

    stage_costs = merge_stage_costs(state["stage_costs"], "analysis", cost_metrics)
    known_total_cost = compute_overall_cost(stage_costs)
    
    return {
        "vulnerability_report_path": path,
        "analysis_start_time": start_time,
        "analysis_end_time": end_time,
        "stage_costs": stage_costs,
        "known_total_cost": known_total_cost,
    }


def evaluation_node(state: AnalysisState) -> dict:
    """Evaluate findings to filter out false positives."""
    start_time = datetime.now()
    print(f"\n[EVALUATION] Stage started at: {start_time.strftime('%Y-%m-%d %H:%M:%S')}")
    
    preset = state["preset"]
    output_path = os.path.join(state["output_dir"], "confirmed_vulnerabilities.md")
    artifacts_dir = os.path.join(state["output_dir"], "evaluation_artifacts")
    path, cost_metrics = evaluate_vulnerabilities(
        state["repo_path"],
        vulnerability_report_path=state["vulnerability_report_path"],
        output_path=output_path,
        subagent_model_config=preset.subagent_evaluation,
        artifacts_dir=artifacts_dir,
        model_config=preset.evaluation,
        retry_config=preset.retry,
    )
    
    end_time = datetime.now()
    elapsed = format_elapsed_time(start_time, end_time)
    print(f"[EVALUATION] Stage completed at: {end_time.strftime('%Y-%m-%d %H:%M:%S')} (elapsed: {elapsed})")
    print_stage_cost_summary("EVALUATION", cost_metrics)

    stage_costs = merge_stage_costs(state["stage_costs"], "evaluation", cost_metrics)
    known_total_cost = compute_overall_cost(stage_costs)
    
    return {
        "confirmed_vulnerabilities_path": path,
        "evaluation_start_time": start_time,
        "evaluation_end_time": end_time,
        "stage_costs": stage_costs,
        "known_total_cost": known_total_cost,
    }


def confirmer_node(state: AnalysisState) -> dict:
    """Extract confirmed issues into a structured Pydantic model (single LLM call)."""
    start_time = datetime.now()
    print(f"\n[EXTRACTION] Stage started at: {start_time.strftime('%Y-%m-%d %H:%M:%S')}")
    
    preset = state["preset"]
    with open(state["confirmed_vulnerabilities_path"], "r") as f:
        confirmed_text = f.read()
    report, cost_metrics = extract_confirmed_issues(
        confirmed_text,
        model_config=preset.extraction,
        retry_config=preset.retry,
    )
    
    end_time = datetime.now()
    elapsed = format_elapsed_time(start_time, end_time)
    print(f"[EXTRACTION] Stage completed at: {end_time.strftime('%Y-%m-%d %H:%M:%S')} (elapsed: {elapsed})")
    print_stage_cost_summary("EXTRACTION", cost_metrics)

    stage_costs = merge_stage_costs(state["stage_costs"], "extraction", cost_metrics)
    known_total_cost = compute_overall_cost(stage_costs)
    
    return {
        "confirmed_issues": report,
        "extraction_start_time": start_time,
        "extraction_end_time": end_time,
        "stage_costs": stage_costs,
        "known_total_cost": known_total_cost,
    }


# ---------------------------------------------------------------------------
# Graph construction
# ---------------------------------------------------------------------------
def build_graph() -> StateGraph:
    """
    Build the prompt-chaining analysis graph.

    Current chain:  START -> introduction -> security_analysis -> evaluation -> confirmer -> END

    To extend the pipeline, add new nodes and wire them in sequence:
        builder.add_node("dependency_audit", dependency_audit_node)
        builder.add_edge("evaluation", "dependency_audit")
        builder.add_edge("dependency_audit", END)
    """
    builder = StateGraph(AnalysisState)

    # Nodes
    builder.add_node("introduction", introduction_node)
    builder.add_node("security_analysis", security_analysis_node)
    builder.add_node("evaluation", evaluation_node)
    builder.add_node("confirmer", confirmer_node)

    # Edges (prompt-chain: each step feeds into the next)
    builder.add_edge(START, "introduction")
    builder.add_edge("introduction", "security_analysis")
    builder.add_edge("security_analysis", "evaluation")
    builder.add_edge("evaluation", "confirmer")
    builder.add_edge("confirmer", END)

    return builder.compile()


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
# Ordered pipeline node names, exposed so callers can stream progress and know
# the total number of stages up front.
PIPELINE_NODES: tuple[str, ...] = (
    "introduction",
    "security_analysis",
    "evaluation",
    "confirmer",
)


def build_initial_state(
    repo_path: str,
    user_focus: str = "",
    preset: ResolvedPreset | None = None,
    output_dir: str | None = None,
) -> AnalysisState:
    """Build the initial pipeline state dict.

    Shared by :func:`run_analysis` and external callers (e.g. the scan worker)
    that drive the graph themselves via ``build_graph().stream(...)``.
    """
    if output_dir is None:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_dir = os.path.abspath(os.path.join(".pipeline_outputs", timestamp))
    os.makedirs(output_dir, exist_ok=True)

    return {
        "repo_path": repo_path,
        "user_focus": user_focus,
        "preset": preset,
        "output_dir": output_dir,
        "review_areas_path": "",
        "vulnerability_report_path": "",
        "confirmed_vulnerabilities_path": "",
        "confirmed_issues": None,
        "introduction_start_time": None,
        "introduction_end_time": None,
        "analysis_start_time": None,
        "analysis_end_time": None,
        "evaluation_start_time": None,
        "evaluation_end_time": None,
        "extraction_start_time": None,
        "extraction_end_time": None,
        "stage_costs": {},
        "known_total_cost": None,
    }


def run_analysis(repo_path: str, user_focus: str = "", preset_name: str = "", output_dir: str | None = None) -> AnalysisState:
    """Execute the full security-analysis pipeline and return final state."""

    preset: ResolvedPreset | None = None
    if preset_name:
        preset = load_preset(preset_name)
        print(f"Using preset '{preset_name}' — models: "
              f"intro={preset.intro.name}, analysis={preset.analysis.name}, "
              f"subagent_analysis={preset.subagent_analysis.name}, "
              f"subagent_evaluation={preset.subagent_evaluation.name}, "
              f"evaluation={preset.evaluation.name}, extraction={preset.extraction.name}, ")

    initial_state = build_initial_state(repo_path, user_focus, preset, output_dir)
    print(f"Pipeline outputs directory: {initial_state['output_dir']}")

    graph = build_graph()
    final_state = graph.invoke(initial_state)
    return final_state


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Run security analysis pipeline on a repository."
    )
    parser.add_argument("repo_path", help="Local path to the repository to analyse.")
    parser.add_argument(
        "--focus",
        default="",
        help="Optional brief suggestion about which parts of the code are most important for analysis."
    )
    parser.add_argument(
        "--preset",
        default="openai-review",
        metavar="NAME",
        help="Named model preset from model_presets.json (e.g. 'azure-one', 'deep-review'). "
             "Defaults to 'openai-review'."
    )
    parser.add_argument(
        "--list-presets",
        action="store_true",
        help="List available preset names and exit."
    )
    parser.add_argument(
        "--output-dir",
        default=None,
        help="Directory to store per-run pipeline outputs. "
             "Defaults to ./.pipeline_outputs/<timestamp>/."
    )
    args = parser.parse_args()

    apply_model_price_overrides()

    if args.list_presets:
        presets = list_presets()
        if presets:
            print("Available presets:")
            for name in presets:
                print(f"  - {name}")
        else:
            print("No presets found. Place model_presets.json in the src/ directory.")
        return

    overall_start = datetime.now()
    print(f"\n{'='*70}")
    print(f"Analysis started at: {overall_start.strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'='*70}\n")
    
    result = run_analysis(args.repo_path, args.focus, args.preset, output_dir=args.output_dir)

    overall_end = datetime.now()

    print(f"\n{'='*70}")
    print("EXECUTION SUMMARY")
    print(f"{'='*70}")
    
    print("\n===== Review Areas Report =====")
    print(f"Saved to: {result['review_areas_path']}")
    if result.get("introduction_start_time") and result.get("introduction_end_time"):
        intro_elapsed = format_elapsed_time(result["introduction_start_time"], result["introduction_end_time"])
        print(f"Duration: {intro_elapsed}")
    intro_cost = result.get("stage_costs", {}).get("introduction", {}).get("total_cost")
    print(f"Cost: {format_cost(intro_cost)}")

    print("\n===== Security Analysis Report =====")
    print(f"Saved to: {result['vulnerability_report_path']}")
    if result.get("analysis_start_time") and result.get("analysis_end_time"):
        analysis_elapsed = format_elapsed_time(result["analysis_start_time"], result["analysis_end_time"])
        print(f"Duration: {analysis_elapsed}")
    analysis_cost = result.get("stage_costs", {}).get("analysis", {}).get("total_cost")
    print(f"Cost: {format_cost(analysis_cost)}")

    print("\n===== Confirmed Vulnerabilities Report =====")
    print(f"Saved to: {result['confirmed_vulnerabilities_path']}")
    if result.get("evaluation_start_time") and result.get("evaluation_end_time"):
        eval_elapsed = format_elapsed_time(result["evaluation_start_time"], result["evaluation_end_time"])
        print(f"Duration: {eval_elapsed}")
    evaluation_cost = result.get("stage_costs", {}).get("evaluation", {}).get("total_cost")
    print(f"Cost: {format_cost(evaluation_cost)}")

    print("\n===== Structured Confirmed Issues =====")
    if result["confirmed_issues"] is not None:
        print(result["confirmed_issues"].model_dump_json(indent=2))
    else:
        print("No structured output produced.")
    if result.get("extraction_start_time") and result.get("extraction_end_time"):
        extraction_elapsed = format_elapsed_time(result["extraction_start_time"], result["extraction_end_time"])
        print(f"Duration: {extraction_elapsed}")
    extraction_cost = result.get("stage_costs", {}).get("extraction", {}).get("total_cost")
    print(f"Cost: {format_cost(extraction_cost)}")

    print(f"\n{'='*70}")
    print("TIMING DETAILS")
    print(f"{'='*70}")
    if result.get("introduction_start_time") and result.get("introduction_end_time"):
        print(f"Introduction:  {format_elapsed_time(result['introduction_start_time'], result['introduction_end_time'])}")
    if result.get("analysis_start_time") and result.get("analysis_end_time"):
        print(f"Analysis:      {format_elapsed_time(result['analysis_start_time'], result['analysis_end_time'])}")
    if result.get("evaluation_start_time") and result.get("evaluation_end_time"):
        print(f"Evaluation:    {format_elapsed_time(result['evaluation_start_time'], result['evaluation_end_time'])}")
    if result.get("extraction_start_time") and result.get("extraction_end_time"):
        print(f"Extraction:    {format_elapsed_time(result['extraction_start_time'], result['extraction_end_time'])}")

    print(f"\n{'='*70}")
    print("COST DETAILS")
    print(f"{'='*70}")
    stage_costs = result.get("stage_costs", {})
    for stage_name in ["introduction", "analysis", "evaluation", "extraction"]:
        metrics = stage_costs.get(stage_name, {})
        print(f"{stage_name.capitalize()}: {format_cost(metrics.get('total_cost'))}")
        per_usage = metrics.get("per_usage_cost", {}) if isinstance(metrics, dict) else {}
        if isinstance(per_usage, dict) and per_usage:
            for usage_id, usage_cost in per_usage.items():
                print(f"  - {usage_id}: {format_cost(usage_cost)}")

    total_elapsed = format_elapsed_time(overall_start, overall_end)
    print(f"{'-'*70}")
    print(f"TOTAL TIME:    {total_elapsed}")
    print(f"TOTAL COST:    {format_cost(result.get('known_total_cost'))}")
    
    print(f"\nAnalysis completed at: {overall_end.strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'='*70}\n")

if __name__ == "__main__":
    main()
