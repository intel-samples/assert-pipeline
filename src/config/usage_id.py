# Copyright (C) 2026 Intel Corporation
# SPDX-License-Identifier: MIT
"""Helpers for consistent LLM usage_id generation."""

import secrets
import string


def randomized_usage_id(base: str, suffix_len: int = 5) -> str:
    """Return usage id like '<base>-abc12' with random alphanumeric suffix."""
    alphabet = string.ascii_lowercase + string.digits
    suffix = "".join(secrets.choice(alphabet) for _ in range(suffix_len))
    return f"{base}-{suffix}"
