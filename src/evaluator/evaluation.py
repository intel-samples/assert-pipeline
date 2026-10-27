# Copyright (C) 2026 Intel Corporation
# SPDX-License-Identifier: MIT
"""
Vulnerability evaluator agent module.

Wraps an openhands.sdk agent with the evaluation.j2 system prompt
to filter out false positives from the security analysis report by
delegating each finding to a dedicated subagent for verification
against the full repository context.
"""
import argparse
import os
import uuid
from typing import Any

from openhands.sdk import LLM, Agent, AgentContext, Conversation, Tool, register_agent
from openhands.sdk.context import Skill
from openhands.tools.file_editor import FileEditorTool
from openhands.tools.task_tracker import TaskTrackerTool
from openhands.tools.task import TaskToolSet
from openhands.tools.delegate import DelegationVisualizer
from openhands.tools.terminal import TerminalTool

from config.preset_config import ModelEntry, RetryConfig, make_subagent_llm_factory
from config.cost_metrics import extract_conversation_cost_metrics

_PROMPT_PATH = os.path.join(os.path.dirname(__file__), "evaluation.j2")
_PROMPT_PATH_FINDING_EVALUATOR = os.path.join(os.path.dirname(__file__), "finding_evaluator.j2")


def create_finding_evaluator_agent(llm: LLM) -> Agent:
    skills = [
        Skill(
            name="vulnerability evaluation",
            content=(
                "You evaluate a single security finding against the full repository context. "
                "You determine if it is a true positive or false positive by checking whether "
                "the code is production, reachable, and unmitigated. "
                "You are thorough in tracing call graphs and searching for existing mitigations."
            ),
            trigger=None,
        )
    ]

    return Agent(
        llm=llm,
        tools=[Tool(name=TerminalTool.name), Tool(name=FileEditorTool.name), Tool(name=TaskTrackerTool.name)],
        agent_context=AgentContext(
            skills=skills,
            system_message_suffix="Evaluate the provided security finding against the full repository context",
        ),
        system_prompt_filename=_PROMPT_PATH_FINDING_EVALUATOR,
    )


def evaluate_vulnerabilities(
    repo_path: str,
    vulnerability_report_path: str,
    output_path: str,
    subagent_model_config: ModelEntry,
    artifacts_dir: str | None = None,
    model_config: ModelEntry | None = None,
    retry_config: RetryConfig | None = None,
) -> tuple[str, dict[str, Any]]:
    """Evaluate identified vulnerabilities and filter out false positives.

    For each vulnerability from the security analysis report, the
    orchestrator agent delegates evaluation to a dedicated subagent
    (one per finding) that examines the broader repository context to
    determine whether the finding is a true positive or false positive.

    Parameters
    ----------
    repo_path:
        Local filesystem path to the repository.
    vulnerability_report_path:
        Filesystem path to the Security Analysis Report produced by the
        analyzer step.
    output_path:
        Filesystem path where the final Confirmed Vulnerabilities Report will
        be saved.
    artifacts_dir:
        Working directory for intermediate JSON/JSONL artifacts. Defaults to
        ``<dirname(output_path)>/evaluation_artifacts``.

    Returns
    -------
    str
        Filesystem path to the saved Confirmed Vulnerabilities Report.
    """
    with open(vulnerability_report_path, "r") as f:
        vulnerability_report = f.read()

    if artifacts_dir is None:
        artifacts_dir = os.path.join(
            os.path.dirname(os.path.abspath(output_path)), "evaluation_artifacts"
        )
    os.makedirs(artifacts_dir, exist_ok=True)
    os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)

    r = retry_config

    # Main orchestration LLM
    m = model_config
    llm = m.to_llm(
        usage_id="main_evaluator_run",
        timeout=r.main_llm_timeout,
        retry=r,
    )

    # Per-subagent LLM factory (fresh LLM with a unique usage_id each call)
    make_subagent_llm = make_subagent_llm_factory(subagent_model_config, r)

    # Register subagent with a per-invocation LLM via closure
    register_agent(
        "finding_evaluator_agent",
        factory_func=lambda _: create_finding_evaluator_agent(make_subagent_llm()),
        description="Agent that evaluates a single security finding against the full repository context to determine if it is a true positive or false positive.",
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
                                visualizer=DelegationVisualizer(name="Evaluator"),
                                persistence_dir="./.agent_conversations_evaluation"
    )

    user_message = (
        f"Evaluate the following security analysis report. For every "
        f"finding listed, delegate its evaluation to a dedicated subagent "
        f"(one subagent per finding) to determine whether it is a true "
        f"positive or a false positive by examining the repository context.\n\n"
        f"{vulnerability_report}\n\n"
        f"Parse every finding and dispatch each one to a finding_evaluator_agent "
        f"subagent. Use `{artifacts_dir}` as the working directory for intermediate "
        f"JSON/JSONL artifacts. When the merge is complete, write the final Confirmed "
        f"Vulnerabilities Report (verbatim, no additional commentary) to the absolute "
        f"path `{output_path}` using the file editor tool. That file is the sole "
        f"deliverable; do not paste its contents back into the conversation."
    )

    conversation.send_message(user_message)
    conversation.run()

    if not os.path.isfile(output_path) or os.path.getsize(output_path) == 0:
        raise RuntimeError(
            f"Evaluation step did not produce a non-empty report at {output_path}"
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
    """Resume a previously stopped evaluation conversation interactively.

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
        usage_id="main_evaluator_resume",
        timeout=r.main_llm_timeout,
        retry=r,
    )

    # Per-subagent LLM factory (fresh LLM with a unique usage_id each call)
    make_subagent_llm = make_subagent_llm_factory(subagent_model_config, r)

    # Register subagent with a per-invocation LLM via closure
    register_agent(
        "finding_evaluator_agent",
        factory_func=lambda _: create_finding_evaluator_agent(make_subagent_llm()),
        description="Agent that evaluates a single security finding against the full repository context to determine if it is a true positive or false positive.",
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
        visualizer=DelegationVisualizer(name="Evaluator"),
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
        description="Evaluate vulnerabilities and filter out false positives."
    )
    subparsers = parser.add_subparsers(dest="command", help="Available subcommands")

    # "run" subcommand (default behavior)
    run_parser = subparsers.add_parser("run", help="Run a new vulnerability evaluation.")
    run_parser.add_argument(
        "repo_path",
        help="Path to the directory where the repository for analysis is located."
    )
    run_parser.add_argument(
        "findings_path",
        help="Path to the Security Analysis Report file describing findings to evaluate."
    )
    run_parser.add_argument(
        "--output", default="./confirmed_vulnerabilities.md",
        help="Filesystem path where the final Confirmed Vulnerabilities Report will be saved."
    )
    run_parser.add_argument(
        "--artifacts-dir", default=None,
        help="Working directory for intermediate evaluation artifacts."
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
        "--persistence-dir", default="./.agent_conversations_evaluation",
        help="Directory where conversation state is persisted."
    )
    resume_parser.add_argument(
        "--output", default=None,
        help="Optional filesystem path the agent should write the final report to."
    )
    resume_parser.add_argument(
        "--artifacts-dir", default=None,
        help="Optional working directory for intermediate evaluation artifacts."
    )
    resume_parser.add_argument(
        "--preset", default="deep-review",
        help="Named model preset from model_presets.json."
    )

    args = parser.parse_args()

    if args.command == "run":
        from config.preset_config import load_preset
        preset = load_preset(args.preset)
        result, cost_metrics = evaluate_vulnerabilities(
            args.repo_path,
            vulnerability_report_path=args.findings_path,
            output_path=args.output,
            subagent_model_config=preset.subagent_evaluation,
            artifacts_dir=args.artifacts_dir,
            model_config=preset.evaluation,
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
            subagent_model_config=preset.subagent_evaluation,
            model_config=preset.evaluation,
            retry_config=preset.retry,
            output_path=args.output,
            artifacts_dir=args.artifacts_dir,
        )

    else:
        parser.print_help()
