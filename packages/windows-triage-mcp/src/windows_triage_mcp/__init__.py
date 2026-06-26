"""Windows Triage MCP Server.

Provides offline forensic file/hash/indicator triage capabilities
for Claude Code via the Model Context Protocol.
"""

from importlib.metadata import version

__version__ = version("windows-triage-mcp")

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
