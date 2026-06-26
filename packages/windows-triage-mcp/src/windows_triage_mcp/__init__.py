"""Windows Triage MCP Server.

Provides offline forensic file/hash/indicator triage capabilities
for Claude Code via the Model Context Protocol.
"""

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("windows-triage-mcp")
except PackageNotFoundError:  # source tree / dist not installed — avoid import-time crash
    __version__ = "0.0.0.dev0"

from .config import Config, get_config, reset_config, set_config
from .exceptions import (
    ConfigurationError,
    DatabaseError,
    ValidationError,
    WindowsTriageError,
)

__all__ = [
    "Config",
    "get_config",
    "set_config",
    "reset_config",
    "ConfigurationError",
    "WindowsTriageError",
    "ValidationError",
    "DatabaseError",
]
