"""Examiner identity resolution.

Priority: --examiner flag > SIFT_EXAMINER env > SIFT_ANALYST env (deprecated) >
~/.sift/config.yaml > OS username.
"""

from __future__ import annotations

import os
import re
import sys
from pathlib import Path

import yaml

_EXAMINER_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,19}$")


def _sanitize_slug(raw: str) -> str:
    slug = re.sub(r"[^a-z0-9-]", "-", raw.lower()).strip("-")[:20]
    if not slug:
        return "unknown"
    slug = slug.lstrip("-")
    return slug if slug else "unknown"


def get_examiner_identity(flag_override: str | None = None) -> dict:
    """Resolve examiner identity from all sources.

    Returns dict with keys: os_user, examiner, examiner_source,
    and backward-compat aliases analyst/analyst_source.
    """
    os_user = os.environ.get("USER", os.environ.get("USERNAME", "unknown"))

    def _result(examiner: str, source: str) -> dict:
        examiner = _sanitize_slug(examiner)
        if not examiner:
            print(
                f"Warning: empty examiner identity from source '{source}'. "
                f"Falling back to OS user '{os_user}'.",
                file=sys.stderr,
            )
            examiner = os_user
            source = "os_user"
        return {
            "os_user": os_user,
            "examiner": examiner,
            "examiner_source": source,
            "analyst": examiner,
            "analyst_source": source,
        }

    if flag_override:
        return _result(flag_override, "flag")

    env_examiner = os.environ.get("SIFT_EXAMINER")
    if env_examiner:
        return _result(env_examiner, "env")

    env_analyst = os.environ.get("SIFT_ANALYST")
    if env_analyst:
        return _result(env_analyst, "env")

    config_path = Path.home() / ".sift" / "config.yaml"
    if config_path.exists():
        try:
            with open(config_path) as f:
                config = yaml.safe_load(f) or {}
            examiner = config.get("examiner") or config.get("analyst")
            if examiner:
                return _result(examiner, "config")
        except (OSError, yaml.YAMLError) as e:
            print(
                f"Warning: could not read identity config {config_path}: {e}",
                file=sys.stderr,
            )

    return _result(os_user, "os_user")


def warn_if_unconfigured(identity: dict) -> None:
    if identity["examiner_source"] == "os_user":
        print(
            f"No examiner identity configured. Using OS user '{identity['os_user']}'.\n"
            f"Run 'sift config --examiner <name>' to set your identity.\n",
            file=sys.stderr,
        )
