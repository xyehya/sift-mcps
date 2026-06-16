"""Environment variable parsing helpers for SIFT-platform MCP servers.

Canonical implementation shared by all SIFT-platform MCPs via sift-common.
"""

from __future__ import annotations

import logging
import os

logger = logging.getLogger(__name__)


def parse_int_env(name: str, default: int) -> int:
    """Parse integer environment variable with fallback to default.

    Logs a warning if the value is invalid instead of crashing.
    """
    value = os.getenv(name)
    if value is None:
        return default
    try:
        return int(value)
    except ValueError:
        logger.warning(
            "Invalid integer value for %s: %r, using default %d", name, value, default
        )
        return default


def parse_float_env(name: str, default: float) -> float:
    """Parse float environment variable with fallback to default.

    Logs a warning if the value is invalid instead of crashing.
    """
    value = os.getenv(name)
    if value is None:
        return default
    try:
        return float(value)
    except ValueError:
        logger.warning(
            "Invalid float value for %s: %r, using default %s", name, value, default
        )
        return default


def parse_set_env(name: str) -> frozenset[str]:
    """Parse comma-separated environment variable into a frozenset.

    Empty values and whitespace-only values are filtered out.
    Values are stripped but NOT lowercased (type names are case-sensitive).
    """
    value = os.getenv(name)
    if not value:
        return frozenset()

    items = []
    for item in value.split(","):
        item = item.strip()
        if item:
            items.append(item)

    return frozenset(items)


def parse_bool_env(name: str, default: bool = False) -> bool:
    """Parse boolean environment variable with fallback to default.

    Truthy values: ``"true"``, ``"1"``, ``"yes"``, ``"on"`` (case-insensitive).
    """
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in ("true", "1", "yes", "on")


class SecretStr:
    """String type that hides its value in logs and repr.

    Prevents accidental credential exposure in logs, error messages, or
    debug output.
    """

    def __init__(self, value: str) -> None:
        self._value = value

    def get_secret_value(self) -> str:
        return self._value

    def __repr__(self) -> str:
        return "SecretStr('***')"

    def __str__(self) -> str:
        return "***"

    def __eq__(self, other: object) -> bool:
        if isinstance(other, SecretStr):
            return self._value == other._value
        return False

    def __hash__(self) -> int:
        return hash(self._value)

    def __bool__(self) -> bool:
        return bool(self._value)

    def __len__(self) -> int:
        return len(self._value)
