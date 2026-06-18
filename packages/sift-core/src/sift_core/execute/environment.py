"""Environment detection: WSL, SIFT version, tool availability."""

from __future__ import annotations

import logging
import os
import shutil
import subprocess
from pathlib import Path

logger = logging.getLogger(__name__)


def is_wsl() -> bool:
    """Detect if running under WSL."""
    try:
        with open("/proc/version") as f:
            return "microsoft" in f.read().lower()
    except (FileNotFoundError, PermissionError, OSError) as e:
        logger.debug("Cannot read /proc/version for WSL detection: %s", e)
        return False


def get_sift_version() -> str | None:
    """Detect SIFT workstation version if installed."""
    version_file = Path("/etc/sift-version")
    try:
        if version_file.exists():
            return version_file.read_text().strip()
    except OSError as e:
        logger.debug("Cannot read SIFT version file: %s", e)
    # Check cast package
    try:
        result = subprocess.run(
            ["cast", "--version"], capture_output=True, text=True, timeout=5
        )
        if result.returncode == 0:
            return result.stdout.strip()
    except (FileNotFoundError, subprocess.TimeoutExpired) as e:
        logger.debug("SIFT cast version check failed: %s", e)
    except OSError as e:
        logger.debug("SIFT cast version check OS error: %s", e)
    return None


def find_binary(name: str, extra_paths: list[str] | None = None) -> str | None:
    """Find a binary on PATH or in common forensic tool locations.

    Resolution order (fail-closed — returns None if nothing resolves):
      1. ``shutil.which(name)`` (PATH).
      2. Fallback dirs: ``extra_paths`` if given, else the built-in forensic
         locations plus every ``/opt/*/bin`` directory. For each fallback dir
         ``d`` both ``d/name`` (flat layout) and ``d/name/name`` (per-tool
         subdir layout, e.g. ``/opt/zimmermantools/RECmd/RECmd``) are probed.
    """
    # shutil.which checks PATH
    found = shutil.which(name)
    if found:
        return found

    # Check extra paths
    if extra_paths is not None:
        search_paths = list(extra_paths)
    else:
        search_paths = [
            "/usr/local/bin",
            "/opt/zimmermantools",
            "/opt/volatility3",
            "/opt/hayabusa",
        ]
        # /opt/*/bin — per-tool venv/wrapper bin dirs (bucket-D layout).
        search_paths.extend(str(p) for p in sorted(Path("/opt").glob("*/bin")))

    for d in search_paths:
        base = Path(d)
        for candidate in (base / name, base / name / name):
            if candidate.is_file() and os.access(candidate, os.X_OK):
                return str(candidate)

    return None


def get_environment_info() -> dict:
    """Collect environment information for diagnostics."""
    return {
        "wsl": is_wsl(),
        "sift_version": get_sift_version(),
        "platform": os.uname().sysname,
        "python": os.sys.version,
    }
