# IPAS ASSERT pipeline

> **Disclaimer:** This is sample code provided as-is. Running scans against untrusted code may
> expose the pipeline to prompt injection attacks - only scan repositories you trust.

AI-powered security analysis pipeline that automates vulnerability discovery in source code
repositories. It runs a multi-stage LLM orchestration (LangGraph + OpenHands SDK) that
progressively identifies, evaluates and reports security findings classified by CWE.

```
START → Introduction → Security Analysis → Evaluation → Extraction → END
```

| Stage | Purpose |
|---|---|
| **Introduction** | Traverse the repo, classify it, identify security-relevant review areas |
| **Security Analysis** | Deep CWE-classified analysis using terminal/file tools (agent + subagents) |
| **Evaluation** | Filter false positives — each finding is dispatched to a dedicated subagent |
| **Extraction** | Parse confirmed findings into structured JSON (Pydantic) |

Every stage is a LangGraph node that reads shared state and appends its output for the next stage.

## LLM client stack

The pipeline does **not** talk to model providers directly. All model traffic goes through the
**OpenHands SDK**, which in turn uses **LiteLLM** as its universal client. Consequences you need
to be aware of before configuring anything:

- A model is addressed with a **LiteLLM model string** (e.g. `gpt-5.4-mini`,
  `hosted_vllm/<model>`, `vertex_ai/<model>`, `azure/<deployment>`, `anthropic/<model>`).
- Provider-specific requirements (which env vars a provider needs, whether `base_url` /
  `api_version` are mandatory, how credentials are picked up) are **defined by LiteLLM**, not by
  this repository.
- Anything OpenHands supports for agents, tools and LLM options is available here.

Consult their documentation when adding a provider:

- LiteLLM providers: <https://docs.litellm.ai/docs/providers>
- OpenHands SDK: <https://docs.openhands.dev/sdk>

---

# Step-by-step: running an analysis

## 1. Prepare Docker on the Linux host

Install Docker Engine and the Compose plugin (Debian/Ubuntu example — for other distros follow
<https://docs.docker.com/engine/install/>):

```bash
sudo apt-get update
sudo apt-get install -y ca-certificates curl
curl -fsSL https://get.docker.com | sudo sh
```

Allow your user to run Docker without `sudo`, then re-login so the group takes effect:

```bash
sudo usermod -aG docker "$USER"
newgrp docker
```

Verify:

```bash
docker run --rm hello-world
docker compose version
```

Note your host UID/GID — you will need them later so files created in the container stay
writable on the host:

```bash
id -u && id -g
```

## 2. Clone the repository

```bash
git clone <repo-url>
cd assert-pipeline
```

## 3. Prepare access to LLMs (`src/model_presets.json`)

`src/model_presets.json` holds two things: a **model zoo** (individual model definitions) and
**presets** (which model each pipeline stage uses).

```jsonc
{
  "model_zoo": {
    "openai_gpt-5.4-mini": {
      "model": "gpt-5.4-mini"
    },
    "vllm_gemma4": {
      "model": "hosted_vllm/gemma-4-26b-a4b",
      "base_url": "http://some_ip_address:8000/v1",
      "api_key": "",
      "max_input_tokens": 256000
    }
  },

  "shared": {
    "retry": {
      "num_retries": 5,
      "retry_min_wait": 15,
      "retry_max_wait": 120,
      "retry_multiplier": 2.0,
      "main_llm_timeout": 7200
    }
  },

  "presets": {
    "openai-review": {
      "intro": "openai_gpt-5.4-mini",
      "analysis": "openai_gpt5.6-terra",
      "subagent_analysis": "openai_gpt-5.4-pro",
      "evaluation": "openai_gpt5.6-terra",
      "subagent_evaluation": "openai_gpt5.6-sol",
      "extraction": "openai_gpt-5.4-mini"
    }
  }
}
```

### Model zoo entry fields

| Field | Required | Description |
|---|---|---|
| `model` | yes | LiteLLM model string. The provider prefix decides routing. |
| `base_url` | no | Endpoint override (self-hosted vLLM, gateways, Azure endpoints). |
| `api_key` | no | Per-model key. If omitted, falls back to `LLM_API_KEY` from the environment. |
| `api_version` | no | Provider API version (Azure). Falls back to `LLM_API_VERSION`. |
| `max_input_tokens` | no | Context window cap used for truncation decisions. |

Unset `base_url` / `api_key` / `api_version` fall back to the `LLM_BASE_URL`, `LLM_API_KEY` and
`LLM_API_VERSION` environment variables from `docker/.env`.

### Preset stage keys

Every preset must define all six stages, each pointing to a model-zoo key:

`intro`, `analysis`, `subagent_analysis`, `evaluation`, `subagent_evaluation`, `extraction`

Add your own model and preset, e.g.:

```jsonc
"model_zoo": {
  "my_model": { "model": "<litellm-model-string>" }
},
"presets": {
  "my-review": {
    "intro": "my_model",
    "analysis": "my_model",
    "subagent_analysis": "my_model",
    "evaluation": "my_model",
    "subagent_evaluation": "my_model",
    "extraction": "my_model"
  }
}
```

To keep local endpoints and keys out of Git, put overrides in
`src/model_presets.local.json` — it is deep-merged on top of `model_presets.json`.

## 4. Configure environment variables

Copy the sample env file and fill it in:

```bash
cp docker/.env.example docker/.env
```

```ini
# Required secret — API key for your LLM provider
LLM_API_KEY=<your-api-key>

# Pricing map fetched fresh from LiteLLM upstream; override to pin or mirror it
LITELLM_MODEL_COST_MAP_URL=https://raw.githubusercontent.com/BerriAI/litellm/main/model_prices_and_context_window.json

# Host bindings
LOCAL_UID=1000
LOCAL_GID=1000
SUT_PATH=/home/username/sandbox/repo.under.test
```

| Variable | Description |
|---|---|
| `LLM_API_KEY` | Default API key used by any model-zoo entry without its own `api_key`. |
| `LLM_BASE_URL` | Optional default endpoint for entries without `base_url`. |
| `LLM_API_VERSION` | Optional default API version for entries without `api_version`. |
| `LITELLM_MODEL_COST_MAP_URL` | Source of token pricing data used for cost reporting. |
| `LOCAL_UID` / `LOCAL_GID` | Set to your host `id -u` / `id -g` to avoid root-owned files. |
| `SUT_PATH` | Host path of the repository to scan (see next step). |

Some providers need extra credentials (e.g. Vertex AI service accounts, Bedrock keys). Add the
variables LiteLLM documents for that provider to `docker/.env`; they are passed straight into
the container.

Never commit `docker/.env` — it contains your API key.

## 5. Point the pipeline at the repository to scan

The system under test (SUT) is bind-mounted into the container at `/sut` by
`docker/docker-compose.yml`:

```yaml
volumes:
  - ../src:/pipeline
  - ${SUT_PATH:-../test_project/}:/sut
```

Set `SUT_PATH` in `docker/.env` to the absolute host path of the repository you want to analyse:

```ini
SUT_PATH=/home/username/sandbox/repo.under.test
```

If you prefer, hardcode the path directly in `docker/docker-compose.yml` instead of using the
variable. When `SUT_PATH` is unset, the bundled `test_project/` is mounted, which is handy for a
first smoke run.

## 6. Build and start the container

```bash
cd docker
docker compose up -d
```

This builds the `pipeline` image (Python 3.14, tmux, vim, ripgrep, pipeline
requirements) and starts the `pipeline_sandbox` container in the background.

Check it is up:

```bash
docker compose ps
```

## 7. Enter the container

```bash
docker exec -it pipeline_sandbox bash
```

You land in `/pipeline`, which is the live-mounted `src/` directory — host edits are visible
immediately, no rebuild needed.

## 8. Run the analysis

List the presets available from your configuration:

```bash
python security_analysis.py /sut --list-presets
```

Run the pipeline:

```bash
python security_analysis.py /sut --preset <name> > output.txt 2>&1
```

Example:

```bash
python security_analysis.py /sut --preset openai-review > output.txt 2>&1
```

### CLI arguments

| Argument | Description |
|---|---|
| `repo_path` | Path to the repository inside the container — normally `/sut` |
| `--preset NAME` | Named preset from `model_presets.json`. Defaults to `openai-review` |
| `--focus TEXT` | Hint about which code areas to prioritise |
| `--output-dir DIR` | Where to write per-run outputs. Defaults to `./.pipeline_outputs/<timestamp>/` |
| `--list-presets` | Print available preset names and exit |

Runs are long-lived; starting them inside `tmux` (installed in the image) protects against a
dropped `docker exec` session.

At the start of the Security Analysis stage the agent prompts interactively for extra
instructions:

```
--- Additional instructions (press Enter on empty line to skip) ---
>
```

Type one instruction per line and press Enter on an empty line to submit, or press Enter
immediately to skip. Because the prompt reads from stdin, run the pipeline attached to a
terminal (`docker exec -it`), not detached.

### Output

Per-stage reports are written to the output directory, and a summary with paths, durations and
cost per stage is printed to stdout:

```
===== Review Areas Report =====
===== Security Analysis Report =====
===== Confirmed Vulnerabilities Report =====
===== Structured Confirmed Issues =====
```

The last section is a JSON array of confirmed issues (id, title, CWE, severity, file, lines,
description, impact, recommendation).

---

## Running a single stage: `run` and `resume` modes

The Security Analysis and Evaluation stages can also be driven directly, outside the LangGraph
pipeline. Both modules expose two subcommands:

| Mode | Purpose |
|---|---|
| `run` | Start a fresh conversation for that stage |
| `resume` | Re-attach to a previously stopped conversation and continue it interactively |

Every conversation is persisted, so a run that was interrupted (timeout, crash, dropped session)
can be picked up where it left off instead of being repeated from scratch.

| Stage | Module | Default persistence directory |
|---|---|---|
| Security Analysis | `analyzer/analysis.py` | `./.agent_conversations_analysis` |
| Evaluation | `evaluator/evaluation.py` | `./.agent_conversations_evaluation` |

### `run`

```bash
python -m analyzer.analysis run /sut <review_areas_path> \
  --output ./vulnerability_report.md \
  --artifacts-dir ./analysis_artifacts \
  --preset <name>

python -m evaluator.evaluation run /sut <findings_path> \
  --output ./confirmed_vulnerabilities.md \
  --artifacts-dir ./evaluation_artifacts \
  --preset <name>
```

| Argument | Description |
|---|---|
| `repo_path` | Repository path inside the container — normally `/sut` |
| `review_areas_path` / `findings_path` | Input report produced by the previous stage |
| `--output PATH` | Where the stage report is written |
| `--artifacts-dir DIR` | Working directory for intermediate artifacts |
| `--preset NAME` | Named preset from `model_presets.json` (default `deep-review`) |

### `resume`

```bash
python -m analyzer.analysis resume /sut <conversation_id> \
  --persistence-dir ./.agent_conversations_analysis \
  --output ./vulnerability_report.md \
  --artifacts-dir ./analysis_artifacts \
  --preset <name>

python -m evaluator.evaluation resume /sut <conversation_id> \
  --persistence-dir ./.agent_conversations_evaluation \
  --output ./confirmed_vulnerabilities.md \
  --artifacts-dir ./evaluation_artifacts \
  --preset <name>
```

| Argument | Description |
|---|---|
| `repo_path` | Repository path inside the container — normally `/sut` |
| `conversation_id` | UUID of the conversation to resume |
| `--persistence-dir DIR` | Directory holding the persisted conversation state |
| `--output PATH` | Optional path the agent should write the final report to |
| `--artifacts-dir DIR` | Optional working directory for intermediate artifacts |
| `--preset NAME` | Named preset from `model_presets.json` (default `deep-review`) |

The conversation ID is the sub-directory name under the persistence directory:

```bash
ls ./.agent_conversations_analysis
```

`resume` drops you into an interactive loop: type your message (one line at a time), press Enter
on an empty line to send it, and type `exit` (or Ctrl+D) to leave the session.

```
--- Resume interactive session (type 'exit' or Ctrl+D to quit) ---

Enter message (press Enter on empty line to send, 'exit' to quit):
>
```

Use the same `--preset`, `--output` and `--artifacts-dir` values as the original run so the
agent's system prompt stays consistent.

---

## Smoke test with the bundled project

`test_project/main.c` is an intentionally vulnerable C program (buffer overflows, command
injection, path traversal, use-after-free) used for end-to-end validation. Leave `SUT_PATH`
unset — or point it at `../test_project/` — and run:

```bash
docker exec -it pipeline_sandbox bash
python security_analysis.py /sut --preset <name> > integration_test.txt 2>&1
```

A healthy run reports several Critical/High memory-safety and injection findings after the
evaluation stage has removed false positives.

## Project structure

```
├── docker/
│   ├── Dockerfile                 # Python 3.14 + tmux, vim, ripgrep
│   ├── docker-compose.yml         # pipeline service, /sut and /pipeline mounts
│   └── .env.example               # Environment variable template
├── src/
│   ├── security_analysis.py       # Pipeline entry point (LangGraph state machine)
│   ├── model_presets.json         # Model zoo + preset definitions
│   ├── tools_registry.py          # Optional docs-lookup tool seam
│   ├── requirements.txt           # Python dependencies
│   ├── config/preset_config.py    # Preset loader, validation, env-var fallbacks
│   ├── intro/introduction.py      # Stage 1: review area identification
│   ├── analyzer/analysis.py       # Stage 2: CWE security analysis
│   ├── evaluator/evaluation.py    # Stage 3: false-positive filtering
│   └── extractor/extraction.py    # Stage 4: structured JSON extraction
└── test_project/main.c            # Intentionally vulnerable C program for testing
```

## Troubleshooting

| Symptom | Fix |
|---|---|
| Root-owned files in `src/` or the SUT | Set `LOCAL_UID`/`LOCAL_GID` in `docker/.env` to your `id -u`/`id -g`, then `docker compose up -d --build` |
| `Model presets config not found` | Ensure `src/model_presets.json` exists, or set `MODEL_PRESETS_PATH` |
| Authentication / 401 errors | Check `LLM_API_KEY` in `docker/.env` and the provider requirements in the LiteLLM docs |
| Cost reported as `unavailable` | Model missing from the LiteLLM cost map — add prices via `src/model_prices.local.json` (see `src/model_prices.local.json.example`) |
| `/sut` is empty | `SUT_PATH` points at a non-existent host path; fix it and recreate the container |
| Analysis or evaluation stopped mid-run | Re-attach with `resume` using the conversation ID from the stage's persistence directory instead of restarting the stage |
