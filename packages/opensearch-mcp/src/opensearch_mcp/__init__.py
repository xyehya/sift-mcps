"""OpenSearch MCP server for forensic evidence indexing and querying."""

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("opensearch-mcp")
except PackageNotFoundError:  # source tree / dist not installed — avoid import-time crash
    __version__ = "0.0.0.dev0"
