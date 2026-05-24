"""Local JSON baseline database helpers for windows-triage-mcp."""

from __future__ import annotations

import json
import os
from functools import cached_property
from pathlib import Path
from typing import Any

DEFAULT_DB_DIR = Path("/var/lib/agentir/windows-triage")
DB_DIR_ENV = "AGENTIR_WINDOWS_TRIAGE_DB_DIR"


def get_db_dir() -> Path:
    return Path(os.environ.get(DB_DIR_ENV, str(DEFAULT_DB_DIR)))


def _norm_text(value: str | None) -> str:
    return (value or "").strip().casefold()


def normalize_windows_path(value: str | None) -> str:
    text = _norm_text(value).replace("/", "\\")
    while "\\\\" in text:
        text = text.replace("\\\\", "\\")
    return text


def basename(value: str | None) -> str:
    return normalize_windows_path(value).rsplit("\\", 1)[-1]


class BaselineDB:
    """Lazy loader for optional JSON baseline assets.

    Expected files live under ``AGENTIR_WINDOWS_TRIAGE_DB_DIR``:
    files.json, process_trees.json, services.json, scheduled_tasks.json,
    autoruns.json, registry.json, loldrivers.json, lolbins.json,
    hijackable_dlls.json, pipes.json, and optional metadata.json.
    Each data file may be either a list or ``{"records": [...]}``.
    """

    def __init__(self, root: Path | None = None) -> None:
        self.root = root or get_db_dir()

    def _load_records(self, name: str) -> list[dict[str, Any]]:
        path = self.root / f"{name}.json"
        if not path.is_file():
            return []
        data = json.loads(path.read_text())
        if isinstance(data, list):
            return [r for r in data if isinstance(r, dict)]
        if isinstance(data, dict):
            records = data.get("records", [])
            if isinstance(records, list):
                return [r for r in records if isinstance(r, dict)]
        return []

    @cached_property
    def metadata(self) -> dict[str, Any]:
        path = self.root / "metadata.json"
        if not path.is_file():
            return {}
        data = json.loads(path.read_text())
        return data if isinstance(data, dict) else {}

    @cached_property
    def files(self) -> list[dict[str, Any]]:
        return self._load_records("files")

    @cached_property
    def process_trees(self) -> list[dict[str, Any]]:
        return self._load_records("process_trees")

    @cached_property
    def services(self) -> list[dict[str, Any]]:
        return self._load_records("services")

    @cached_property
    def scheduled_tasks(self) -> list[dict[str, Any]]:
        return self._load_records("scheduled_tasks")

    @cached_property
    def autoruns(self) -> list[dict[str, Any]]:
        return self._load_records("autoruns")

    @cached_property
    def registry(self) -> list[dict[str, Any]]:
        return self._load_records("registry")

    @cached_property
    def loldrivers(self) -> list[dict[str, Any]]:
        return self._load_records("loldrivers")

    @cached_property
    def lolbins(self) -> list[dict[str, Any]]:
        return self._load_records("lolbins")

    @cached_property
    def hijackable_dlls(self) -> list[dict[str, Any]]:
        return self._load_records("hijackable_dlls")

    @cached_property
    def pipes(self) -> list[dict[str, Any]]:
        return self._load_records("pipes")

    @cached_property
    def available(self) -> bool:
        if not self.root.is_dir():
            return False
        return any(self.root.glob("*.json"))

    def stats(self) -> dict[str, Any]:
        collections = {
            "files": len(self.files),
            "process_trees": len(self.process_trees),
            "services": len(self.services),
            "scheduled_tasks": len(self.scheduled_tasks),
            "autoruns": len(self.autoruns),
            "registry": len(self.registry),
            "loldrivers": len(self.loldrivers),
            "lolbins": len(self.lolbins),
            "hijackable_dlls": len(self.hijackable_dlls),
            "pipes": len(self.pipes),
        }
        return {
            "db_dir": str(self.root),
            "db_available": self.available,
            "collections": collections,
            "total_records": sum(collections.values()),
            "metadata": self.metadata,
        }

