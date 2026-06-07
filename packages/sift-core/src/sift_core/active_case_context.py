"""Request-local active-case context for Gateway-owned core tool calls."""

from __future__ import annotations

from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator


@dataclass(frozen=True)
class ActiveCaseContext:
    case_id: str
    case_key: str
    artifact_path: str | None = None
    membership_role: str | None = None

    @property
    def case_dir(self) -> Path | None:
        if not self.artifact_path:
            return None
        return Path(self.artifact_path)


_ACTIVE_CASE_CONTEXT: ContextVar[ActiveCaseContext | None] = ContextVar(
    "sift_active_case_context",
    default=None,
)


def current_active_case() -> ActiveCaseContext | None:
    return _ACTIVE_CASE_CONTEXT.get()


@contextmanager
def use_active_case_context(context: ActiveCaseContext | None) -> Iterator[None]:
    token = _ACTIVE_CASE_CONTEXT.set(context)
    try:
        yield
    finally:
        _ACTIVE_CASE_CONTEXT.reset(token)
