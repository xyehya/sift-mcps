"""Filesystem read helpers used by the case-dashboard portal.

These are pure utility functions that load common file formats from
the case artifact tree.  They carry no module-level state and depend
only on stdlib + PyYAML, so they are safe to import from any context
(routes, tests, CLI).

Extracted from routes.py as part of D4 (XYE-72) to reduce the size
of the portal's main routes file.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path

import yaml

logger = logging.getLogger(__name__)


def _load_json(path: Path) -> list | dict | None:
    """Load a JSON file, return None on missing/corrupt."""
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        logger.warning("Corrupt JSON file: %s", path)
        return None
    except OSError as e:
        logger.warning("Failed to read %s: %s", path, e)
        return None


def _load_yaml(path: Path) -> dict | None:
    """Load a YAML file. Returns None if missing. Raises ValueError on corrupt/unreadable."""
    if not path.exists():
        return None
    try:
        with open(path, encoding="utf-8") as f:
            return yaml.safe_load(f) or {}
    except yaml.YAMLError as e:
        raise ValueError(f"Corrupt YAML: {path}: {e}") from e
    except OSError as e:
        raise ValueError(f"Cannot read YAML: {path}: {e}") from e


def _load_jsonl(path: Path) -> list[dict]:
    """Load a JSONL file, skipping corrupt lines."""
    if not path.exists():
        return []
    entries = []
    try:
        with open(path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    entries.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
    except OSError:
        pass
    return entries
