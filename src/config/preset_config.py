# Copyright (C) 2026 Intel Corporation
# SPDX-License-Identifier: MIT
"""Model-zoo preset configuration loader."""

from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass, field, fields
from pathlib import Path
from typing import TYPE_CHECKING, Callable
from openhands.sdk import LLM

from config.usage_id import randomized_usage_id

_DEFAULT_CONFIG_FILENAME = "model_presets.json"
_LOCAL_OVERRIDE_FILENAME = "model_presets.local.json"
_REQUIRED_STAGES = ("intro", "analysis", "subagent_analysis", "evaluation", "subagent_evaluation", "extraction")
_FEATURE_LIST_MAP = {
    "prompt_cache": "PROMPT_CACHE_MODELS",
    "reasoning_effort": "REASONING_EFFORT_MODELS",
    "extended_thinking": "EXTENDED_THINKING_MODELS",
}


@dataclass
class ModelEntry:
    """A single model from the zoo."""

    name: str
    model: str
    base_url: str | None = None
    api_key: str | None = None
    api_version: str | None = None
    max_input_tokens: int | None = None

    @classmethod
    def from_dict(cls, name: str, raw: dict) -> ModelEntry:
        return cls(
            name=name, model=raw["model"],
            base_url=raw.get("base_url"), api_key=raw.get("api_key"),
            api_version=raw.get("api_version"),
            max_input_tokens=raw.get("max_input_tokens"),
        )

    def resolve_env_fallbacks(self) -> ModelEntry:
        """Fill ``None`` fields from environment variables."""
        return ModelEntry(
            name=self.name, model=self.model,
            base_url=self.base_url or os.getenv("LLM_BASE_URL"),
            api_key=self.api_key or os.getenv("LLM_API_KEY"),
            api_version=self.api_version or os.getenv("LLM_API_VERSION"),
            max_input_tokens=self.max_input_tokens,
        )

    def to_llm(self, usage_id: str = "main", timeout: int = 2700, 
               retry: RetryConfig | None = None) -> LLM:
        """Create an LLM instance from this model config.

        When ``retry`` is provided, its back-off settings are applied to the LLM.
        """
        kwargs = dict(
            model=self.model,
            api_key=self.api_key,
            base_url=self.base_url,
            api_version=self.api_version,
            usage_id=usage_id,
            timeout=timeout,
        )
        if retry is not None:
            kwargs.update(dict(
                num_retries=retry.num_retries,
                retry_min_wait=retry.retry_min_wait,
                retry_max_wait=retry.retry_max_wait,
                retry_multiplier=retry.retry_multiplier,
            ))
        return LLM(**kwargs)


@dataclass
class RetryConfig:
    """Retry / back-off tuning shared across stages."""

    num_retries: int = 20
    retry_min_wait: int = 15
    retry_max_wait: int = 600
    retry_multiplier: float = 2.0
    main_llm_timeout: int = 2700

    @classmethod
    def from_dict(cls, raw: dict | None) -> RetryConfig:
        return cls() if raw is None else cls(
            num_retries=raw.get("num_retries", 20),
            retry_min_wait=raw.get("retry_min_wait", 15),
            retry_max_wait=raw.get("retry_max_wait", 600),
            retry_multiplier=raw.get("retry_multiplier", 2.0),
            main_llm_timeout=raw.get("main_llm_timeout", 2700)
        )

    def validate(self, prefix: str = "shared.retry") -> None:
        for f in fields(self):
            val = getattr(self, f.name)
            if val <= 0:
                raise ValueError(f"{prefix}.{f.name} must be positive, got {val}")


@dataclass
class ResolvedPreset:
    """Fully dereferenced preset ready for stage consumption."""

    name: str
    intro: ModelEntry
    analysis: ModelEntry
    subagent_analysis: ModelEntry
    evaluation: ModelEntry
    subagent_evaluation: ModelEntry
    extraction: ModelEntry
    retry: RetryConfig = field(default_factory=RetryConfig)


def _find_config_path() -> Path | None:
    candidates = [
        Path(os.getenv("MODEL_PRESETS_PATH", "")),
        Path(__file__).resolve().parent.parent / _DEFAULT_CONFIG_FILENAME,
        Path(__file__).resolve().parent.parent.parent / _DEFAULT_CONFIG_FILENAME,
    ]
    for p in candidates:
        if p and p.is_file():
            return p
    return None


def _deep_merge(base: dict, override: dict) -> dict:
    """Recursively merge *override* into *base* (override wins)."""
    merged = dict(base)
    for key, val in override.items():
        if key in merged and isinstance(merged[key], dict) and isinstance(val, dict):
            merged[key] = _deep_merge(merged[key], val)
        else:
            merged[key] = val
    return merged


def _load_config(config_path: str | Path | None) -> tuple[Path, dict]:
    """Locate config, merge local override, return (path, data). Raises FileNotFoundError."""
    path = Path(config_path) if config_path else _find_config_path()
    if path is None or not path.is_file():
        raise FileNotFoundError(
            f"Model presets config not found. Searched for "
            f"'{_DEFAULT_CONFIG_FILENAME}'. Set MODEL_PRESETS_PATH or "
            f"place the file next to the src/ directory."
        )
    with open(path) as fh:
        data = json.load(fh)
    local = path.parent / _LOCAL_OVERRIDE_FILENAME
    if local.is_file():
        with open(local) as fh:
            data = _deep_merge(data, json.load(fh))
    return path, data


def list_presets(config_path: str | Path | None = None) -> list[str]:
    """Return sorted preset names, or empty list if no config found."""
    try:
        _, data = _load_config(config_path)
    except FileNotFoundError:
        return []
    return sorted(data.get("presets", {}).keys())


def load_preset(preset_name: str, config_path: str | Path | None = None) -> ResolvedPreset:
    """Load and fully resolve a named preset."""
    _, data = _load_config(config_path)

    zoo_raw: dict = data.get("model_zoo", {})
    shared_raw: dict = data.get("shared", {})
    presets_raw: dict = data.get("presets", {})

    if not zoo_raw:
        raise ValueError("model_zoo section is empty or missing.")

    zoo: dict[str, ModelEntry] = {}
    for key, entry_raw in zoo_raw.items():
        if "model" not in entry_raw:
            raise ValueError(f"model_zoo['{key}'] is missing required 'model' field.")
        zoo[key] = ModelEntry.from_dict(key, entry_raw)

    if preset_name not in presets_raw:
        available = ", ".join(sorted(presets_raw.keys())) or "(none)"
        raise KeyError(f"Preset '{preset_name}' not found. Available presets: {available}")

    preset_raw = presets_raw[preset_name]
    for stage in _REQUIRED_STAGES:
        if stage not in preset_raw:
            raise KeyError(f"Preset '{preset_name}' is missing required stage '{stage}'.")
        if preset_raw[stage] not in zoo:
            raise KeyError(
                f"Preset '{preset_name}' stage '{stage}' references "
                f"unknown model-zoo key '{preset_raw[stage]}'."
            )
    # Shared retry
    retry_cfg = RetryConfig.from_dict(shared_raw.get("retry"))
    retry_cfg.validate()

    # Resolve stage models
    resolved = {}
    for stage in _REQUIRED_STAGES:
        entry = zoo[preset_raw[stage]].resolve_env_fallbacks()
        resolved[stage] = entry

    return ResolvedPreset(
        name=preset_name,
        intro=resolved["intro"],
        analysis=resolved["analysis"],
        subagent_analysis=resolved["subagent_analysis"],
        evaluation=resolved["evaluation"],
        subagent_evaluation=resolved["subagent_evaluation"],
        extraction=resolved["extraction"],
        retry=retry_cfg,
    )


def make_subagent_llm_factory(
    subagent_model_config: ModelEntry,
    retry_config: RetryConfig
) -> Callable[[], LLM]:
    """Build a factory that creates a fresh subagent LLM on each call.

    Each produced LLM gets a unique ``usage_id`` (via ``randomized_usage_id``)
    so cost utilization is tracked independently for every delegated subagent.
    """
    def factory() -> LLM:
        return subagent_model_config.to_llm(
            usage_id=randomized_usage_id("subagent"),
            timeout=retry_config.main_llm_timeout,
            retry=retry_config
        )

    return factory