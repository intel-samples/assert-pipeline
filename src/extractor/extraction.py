# Copyright (C) 2026 Intel Corporation
# SPDX-License-Identifier: MIT
"""
Confirmed-issues extractor node.

Makes a single LLM call with structured output (Pydantic response_format)
to distil the evaluator's confirmed-vulnerabilities report into a clean,
machine-readable list of issues.  Uses the OpenHands SDK LLM class which
delegates to litellm.
"""

import os
from typing import Any

from pydantic import BaseModel, Field

from openhands.sdk import LLM
from openhands.sdk.llm import Message, TextContent

from config.preset_config import ModelEntry
from config.cost_metrics import extract_completion_cost_metrics

# ---------------------------------------------------------------------------
# Pydantic models – the structured output schema
# ---------------------------------------------------------------------------

class ConfirmedIssue(BaseModel):
    """A single confirmed security issue."""

    id: str = Field(
        description="Finding identifier, e.g. 'F-1'."
    )
    title: str = Field(
        description="Short descriptive title of the vulnerability."
    )
    cwe_id: str = Field(
        description="CWE identifier, e.g. 'CWE-327'."
    )
    cwe_name: str = Field(
        description="Human-readable CWE name."
    )
    severity: str = Field(
        description="Severity level: Critical, High, Medium, Low, or Info."
    )
    file_path: str = Field(
        description="Path to the affected source file."
    )
    line_range: str = Field(
        description="Affected line number(s), e.g. '61-65'."
    )
    description: str = Field(
        description="Detailed explanation of the vulnerability."
    )
    impact: str = Field(
        description="Impact of the vulnerability."
    )
    recommendation: str = Field(
        description="Suggested fix or mitigation."
    )


class ConfirmedIssuesReport(BaseModel):
    """Structured report containing only confirmed security issues."""

    total_evaluated: int = Field(
        description="Total number of findings that were evaluated."
    )
    confirmed_count: int = Field(
        description="Number of confirmed true-positive issues."
    )
    issues: list[ConfirmedIssue] = Field(
        default_factory=list,
        description="List of confirmed security issues."
    )


# ---------------------------------------------------------------------------
# Prompt template
# ---------------------------------------------------------------------------

_SYSTEM_PROMPT_PATH = os.path.join(os.path.dirname(__file__), "extraction.j2")


def _load_system_prompt() -> str:
    with open(_SYSTEM_PROMPT_PATH) as fh:
        return fh.read()


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def extract_confirmed_issues(
    confirmed_vulnerabilities: str,
    model_config: ModelEntry | None = None,
    retry_config=None,
) -> tuple[ConfirmedIssuesReport, dict[str, Any]]:
    """Parse the evaluator output into a structured Pydantic model.

    Makes exactly one LLM call with ``response_format`` set to
    :class:`ConfirmedIssuesReport` so the model returns valid JSON that
    maps directly to the Pydantic schema.

    Parameters
    ----------
    confirmed_vulnerabilities:
        Free-text confirmed-vulnerabilities report produced by the
        evaluator node.

    Returns
    -------
    ConfirmedIssuesReport
        Structured, machine-readable report.
    """
    m = model_config
    r = retry_config
    llm = LLM(
        model=m.model,
        api_key=m.api_key,
        base_url=m.base_url,
        api_version=m.api_version,
        timeout=r.main_llm_timeout if r else 600,
    )

    system_prompt = _load_system_prompt()

    messages: list[Message] = [
        Message(role="system", content=[TextContent(text=system_prompt)]),
        Message(
            role="user",
            content=[
                TextContent(
                    text=(
                        "Extract confirmed true positive security issues from the following Confirmed Vulnerabilities Report and fit them into expected structured format.\n\n"
                        f"### Confirmed Vulnerabilities Report\n"
                        f"{confirmed_vulnerabilities}"
                    )
                )
            ],
        ),
    ]

    response = llm.completion(
        messages,
        response_format=ConfirmedIssuesReport,
    )

    # The response content is JSON matching the schema
    raw_text = response.message.content[0].text
    report = ConfirmedIssuesReport.model_validate_json(raw_text)

    cost_metrics = extract_completion_cost_metrics(response.metrics)
    return report, cost_metrics
