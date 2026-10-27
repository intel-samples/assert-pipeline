# Copyright (C) 2026 Intel Corporation
# SPDX-License-Identifier: MIT
import argparse
import os
from typing import Any

from openhands.sdk import LLM, Agent, Conversation, Tool
from openhands.tools.file_editor import FileEditorTool
from openhands.tools.task_tracker import TaskTrackerTool
from openhands.tools.terminal import TerminalTool

from config.preset_config import ModelEntry
from config.cost_metrics import extract_conversation_cost_metrics


def identify_review_areas(
    repo_path: str,
    output_path: str,
    user_focus: str = "",
    model_config: ModelEntry | None = None,
    retry_config=None,
) -> tuple[str, dict[str, Any]]:
    """Traverse the repository and identify security-relevant review areas.

    Parameters
    ----------
    repo_path:
        Local filesystem path to the repository to analyse.
    output_path:
        Filesystem path where the Review Areas Report will be saved.
    user_focus:
        Optional brief suggestion about which parts of the code are most important
        for analysis.

    Returns
    -------
    str
        Filesystem path to the saved Review Areas Report.
    """
    m = model_config
    r = retry_config

    os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)

    llm = LLM(
        model=m.model,
        api_key=m.api_key,
        base_url=m.base_url,
        api_version=m.api_version,
        timeout=r.main_llm_timeout if r else 600,
    )

    agent = Agent(
        llm=llm,
        tools=[
            Tool(name=TerminalTool.name),
            Tool(name=FileEditorTool.name),
            Tool(name=TaskTrackerTool.name),
        ],
        system_prompt_filename=os.path.join(os.path.dirname(__file__), "introduction.j2"),
        system_prompt_kwargs={"final_report_path": output_path},
    )

    conversation = Conversation(agent=agent, workspace=repo_path)

    if user_focus:
        user_focus_message = f"Put highest attention to following part of the system: {user_focus}"
    else:
        user_focus_message = ""

    conversation.send_message(
        "Traverse the repository and identify all the areas that may contain "
        "security vulnerabilities. Focus on places where user can interact with the system, communication protocols, intensive "
        "memory handling, cryptographic operations, and security-critical features. "
        "Produce the Review Areas Report as described in your instructions."
        f"\n{user_focus_message}"
        f"\n\nWhen done, save the final Review Areas Report (and nothing else, no commentary) to the absolute path `{output_path}` using the file editor tool. This file is the deliverable; the report must be written there verbatim."
    )
    conversation.run()

    if not os.path.isfile(output_path) or os.path.getsize(output_path) == 0:
        raise RuntimeError(
            f"Introduction step did not produce a non-empty report at {output_path}"
        )
    cost_metrics = extract_conversation_cost_metrics(conversation)
    return output_path, cost_metrics


if __name__ == "__main__":
    from config.preset_config import load_preset

    parser = argparse.ArgumentParser(
        description="Identify security-relevant review areas in a repository."
    )
    parser.add_argument(
        "repo_path",
        help="Path to the directory where the repository for analysis is located."
    )
    parser.add_argument(
        "--preset", default="deep-review",
        help="Named model preset from model_presets.json."
    )
    parser.add_argument(
        "--output", default="./review_areas.md",
        help="Filesystem path where the Review Areas Report will be saved."
    )
    args = parser.parse_args()

    preset = load_preset(args.preset)
    result, _ = identify_review_areas(
        args.repo_path,
        output_path=args.output,
        model_config=preset.intro,
        retry_config=preset.retry,
    )
    print(result)

