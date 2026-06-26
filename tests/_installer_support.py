"""Shared helpers for the installer test modules (``test_installer_*.py``).

These tests drive individual installer functions in isolation by ``source``-ing
``install.sh`` in a subshell (the ``main`` guard keeps sourcing side-effect-free
since #18). ``REPO_ROOT`` / ``INSTALL_SH`` / ``LIB_DIR`` and the ``run_bash``
subshell driver were duplicated byte-for-byte across
``test_installer_uv_pin_and_tools.py`` and ``test_installer_modularization.py``;
they live here so a change to how the installer must be sourced is made once.
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
INSTALL_SH = REPO_ROOT / "install.sh"
LIB_DIR = REPO_ROOT / "lib"


def run_bash(
    script: str, env: dict[str, str] | None = None
) -> subprocess.CompletedProcess[str]:
    """Run a bash snippet (typically one that ``source``s install.sh) from a
    clean, minimal env with cwd at the repo root."""
    full_env = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "HOME": os.environ.get("HOME", "/tmp"),
    }
    if env:
        full_env.update(env)
    return subprocess.run(
        ["bash", "-c", script],
        cwd=str(REPO_ROOT),
        capture_output=True,
        text=True,
        encoding="utf-8",
        env=full_env,
    )
