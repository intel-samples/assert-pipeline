# Copyright (C) 2026 Intel Corporation
# SPDX-License-Identifier: MIT
"""
Security analysis agent module.

Wraps an openhands.sdk agent with the security_analysis.j2 system prompt
to perform CWE-classified, standards-aware security review of repository
code areas identified by the introductory step.
"""
import argparse
import os

import uuid
import litellm
from litellm import register_model
from typing import Any
from openhands.sdk import LLM, Agent, AgentContext, Conversation, Tool, register_agent
from openhands.tools.file_editor import FileEditorTool
from openhands.sdk.context import Skill
from openhands.tools.task_tracker import TaskTrackerTool
from openhands.tools.task import TaskToolSet
from openhands.tools.delegate import DelegationVisualizer
from openhands.tools.terminal import TerminalTool
import openhands.sdk.llm.utils.model_features

from config.preset_config import ModelEntry, RetryConfig, make_subagent_llm_factory
from config.cost_metrics import extract_conversation_cost_metrics

_PROMPT_PATH = os.path.join(os.path.dirname(__file__), "analysis.j2")
_PROMPT_PATH_RESEARCHER = os.path.join(os.path.dirname(__file__), "researcher.j2")

def create_security_review_agent(llm: LLM) -> Agent:
    skills = [
        Skill(
            name="vulnerability research",
            content=(
                "As part of your security analysis, you identify vulnerabilities, weaknesses, or areas of concern in the code."
                "For each identified issue, perform targeted research to gather more information about it."
                "You are creative and resourceful in your research, using the tools at your disposal to find relevant information that can help you understand the issue better and provide more insightful analysis."
                "You question assumptions and dig deeper to uncover underlying causes and implications of the vulnerabilities you find."
                "On the other hand you report issues that you are sure are valid and avoid reporting vague or low-confidence issues that cannot be substantiated through research."
            ),
            trigger=None,
        )
    ]

    return Agent(
        llm=llm,
        tools=[Tool(name=TerminalTool.name), Tool(name=FileEditorTool.name), Tool(name=TaskTrackerTool.name)],
        agent_context=AgentContext(
            skills=skills,
            system_message_suffix="Perform thorough security analysis of the provided code areas, identifying vulnerabilities and weaknesses",
        ),
        system_prompt_filename=_PROMPT_PATH_RESEARCHER,
    )

def analyze_repo_security(
    repo_path: str,
    review_areas_path: str,
    output_path: str,
    subagent_model_config: ModelEntry,
    artifacts_dir: str | None = None,
    model_config: ModelEntry | None = None,
    retry_config: RetryConfig | None = None,
) -> tuple[str, dict[str, Any]]:
    """Run security analysis on identified repository areas.

    Parameters
    ----------
    repo_path:
        Local filesystem path to the repository.
    review_areas_path:
        Filesystem path to the Review Areas Report produced by the
        introduction step.
    output_path:
        Filesystem path where the final Security Analysis Report will be saved.
    artifacts_dir:
        Working directory for intermediate batch artifacts. Defaults to
        ``<dirname(output_path)>/analysis_artifacts``.

    Returns
    -------
    str
        Filesystem path to the saved Security Analysis Report.
    """
    with open(review_areas_path, "r") as f:
        review_areas_report = f.read()

    if artifacts_dir is None:
        artifacts_dir = os.path.join(
            os.path.dirname(os.path.abspath(output_path)), "analysis_artifacts"
        )
    os.makedirs(artifacts_dir, exist_ok=True)
    os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)

    r = retry_config

    # Main orchestration LLM
    m = model_config
    llm = m.to_llm(
        usage_id="main_analysis_run",
        timeout=r.main_llm_timeout,
        retry=r
    )

    # Per-subagent LLM factory (fresh LLM with a unique usage_id each call)
    make_subagent_llm = make_subagent_llm_factory(subagent_model_config, r)

    # Register subagent with a per-invocation LLM via closure
    register_agent(
        "security_review_agent",
        factory_func=lambda _: create_security_review_agent(make_subagent_llm()),
        description="Agent that performs security analysis of code areas, identifying vulnerabilities and weaknesses, and conducting research to provide insightful analysis."
    )

    agent = Agent(
        llm=llm,
        tools=[
            Tool(name=TerminalTool.name),
            Tool(name=FileEditorTool.name),
            Tool(name=TaskTrackerTool.name),
            Tool(name=TaskToolSet.name),
        ],
        system_prompt_filename=_PROMPT_PATH,
        system_prompt_kwargs={
            "artifacts_dir": artifacts_dir,
            "final_report_path": output_path,
        },
    )

    conversation = Conversation(agent=agent,
                                workspace=repo_path,
                                visualizer=DelegationVisualizer(name="Delegator"),
                                persistence_dir="./.agent_conversations_analysis",
    )

    user_message = (
        f"Orchestrate a security analysis of the repository areas identified below.\n\n"
        f"{review_areas_report}\n\n"
        f"Pass every file listed in the review areas to subagents "
        f"for detailed analysis of potential security issues. "
        f"Use `{artifacts_dir}` as the working directory for intermediate batch artifacts. "
        f"When the merge is complete, write the final Security Analysis Report (verbatim, no additional commentary) "
        f"to the absolute path `{output_path}` using the file editor tool. "
        f"That file is the sole deliverable; do not paste its contents back into the conversation."
    )

    print("\n--- Additional instructions (press Enter on empty line to skip) ---")
    extra_lines = []
    while True:
        line = input("> ")
        if line == "":
            break
        extra_lines.append(line)
    if extra_lines:
        user_message += "\n\nAdditional instructions:\n" + "\n".join(extra_lines)

    conversation.send_message(user_message)
    conversation.run()

    if not os.path.isfile(output_path) or os.path.getsize(output_path) == 0:
        raise RuntimeError(
            f"Analysis step did not produce a non-empty report at {output_path}"
        )
    cost_metrics = extract_conversation_cost_metrics(conversation)
    return output_path, cost_metrics


def resume_conversation(
    repo_path: str,
    conversation_id: str,
    persistence_dir: str,
    subagent_model_config: ModelEntry,
    model_config: ModelEntry | None = None,
    retry_config: RetryConfig | None = None,
    output_path: str | None = None,
    artifacts_dir: str | None = None,
) -> None:
    """Resume a previously stopped analysis conversation interactively.

    Parameters
    ----------
    repo_path:
        Local filesystem path to the repository (workspace).
    conversation_id:
        ID of the conversation to resume.
    persistence_dir:
        Directory where conversation state was persisted.
    """
    r = retry_config

    # Main orchestration LLM
    m = model_config
    llm = m.to_llm(
        usage_id="main_analysis_resume",
        timeout=r.main_llm_timeout,
        retry=r
    )

    # Per-subagent LLM factory (fresh LLM with a unique usage_id each call)
    make_subagent_llm = make_subagent_llm_factory(subagent_model_config, r)

    # Register subagent with a per-invocation LLM via closure
    register_agent(
        "security_review_agent",
        factory_func=lambda _: create_security_review_agent(make_subagent_llm()),
        description="Agent that performs security analysis of code areas, identifying vulnerabilities and weaknesses, and conducting research to provide insightful analysis."
    )

    agent = Agent(
        llm=llm,
        tools=[
            Tool(name=TerminalTool.name),
            Tool(name=FileEditorTool.name),
            Tool(name=TaskTrackerTool.name),
            Tool(name=TaskToolSet.name),
        ],
        system_prompt_filename=_PROMPT_PATH,
        system_prompt_kwargs={
            "artifacts_dir": artifacts_dir or "",
            "final_report_path": output_path or "",
        },
    )

    conversation = Conversation(
        agent=agent,
        workspace=repo_path,
        visualizer=DelegationVisualizer(name="Delegator"),
        persistence_dir=persistence_dir,
        conversation_id=conversation_id,
    )

    print("\n--- Resume interactive session (type 'exit' or Ctrl+D to quit) ---")
    while True:
        try:
            print("\nEnter message (press Enter on empty line to send, 'exit' to quit):")
            lines = []
            while True:
                line = input("> ")
                if line.strip().lower() == "exit":
                    print("Exiting session.")
                    return
                if line == "":
                    break
                lines.append(line)
            if not lines:
                continue
            user_message = "\n".join(lines)
            conversation.send_message(user_message)
            conversation.run()
        except (EOFError, KeyboardInterrupt):
            print("\nExiting session.")
            return


# Standalone test entry-point
if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Run security analysis on a repository."
    )
    subparsers = parser.add_subparsers(dest="command", help="Available subcommands")

    # "run" subcommand (default behavior)
    run_parser = subparsers.add_parser("run", help="Run a new security analysis.")
    run_parser.add_argument(
        "repo_path",
        help="Path to the directory where the repository for analysis is located."
    )
    run_parser.add_argument(
        "review_areas_path",
        help="Path to the file describing review areas."
    )
    run_parser.add_argument(
        "--output", default="./vulnerability_report.md",
        help="Filesystem path where the final Security Analysis Report will be saved."
    )
    run_parser.add_argument(
        "--artifacts-dir", default=None,
        help="Working directory for intermediate batch artifacts."
    )
    run_parser.add_argument(
        "--preset", default="deep-review",
        help="Named model preset from model_presets.json."
    )

    # "resume" subcommand
    resume_parser = subparsers.add_parser("resume", help="Resume a previously stopped conversation interactively.")
    resume_parser.add_argument(
        "repo_path",
        help="Path to the directory where the repository for analysis is located."
    )
    resume_parser.add_argument(
        "conversation_id",
        help="ID of the conversation to resume."
    )
    resume_parser.add_argument(
        "--persistence-dir", default="./.agent_conversations_analysis",
        help="Directory where conversation state is persisted."
    )
    resume_parser.add_argument(
        "--output", default=None,
        help="Optional filesystem path the agent should write the final report to."
    )
    resume_parser.add_argument(
        "--artifacts-dir", default=None,
        help="Optional working directory for intermediate batch artifacts."
    )
    resume_parser.add_argument(
        "--preset", default="deep-review",
        help="Named model preset from model_presets.json."
    )

    args = parser.parse_args()

    if args.command == "run":
        from config.preset_config import load_preset
        preset = load_preset(args.preset)
        result, cost_metrics = analyze_repo_security(
            args.repo_path,
            review_areas_path=args.review_areas_path,
            output_path=args.output,
            artifacts_dir=args.artifacts_dir,
            model_config=preset.analysis,
            subagent_model_config=preset.subagent_analysis,
            retry_config=preset.retry,
        )
        print(result)
        print("Cost metrics:", cost_metrics)

    elif args.command == "resume":
        from config.preset_config import load_preset
        preset = load_preset(args.preset)
        resume_conversation(
            repo_path=args.repo_path,
            conversation_id=uuid.UUID(args.conversation_id),
            persistence_dir=args.persistence_dir,
            model_config=preset.analysis,
            subagent_model_config=preset.subagent_analysis,
            retry_config=preset.retry,
            output_path=args.output,
            artifacts_dir=args.artifacts_dir,
        )

    else:
        parser.print_help()
