"""Static guard for the OpenSearch client creation boundary.

Agent-facing OpenSearch access must use ``server._get_os()``.  That keeps the
cached, health-checked client behind the same implementation module whose tools
apply active-case index validation.  Direct clients remain necessary only in
the factory itself and the standalone ingest CLI, which is a worker/CLI plane
and not an MCP tool surface.  Every exception is named below so a new raw
client cannot silently become an agent-reachable shortcut.
"""

from __future__ import annotations

import ast
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[3]
_PACKAGES_ROOT = _REPO_ROOT / "packages"
_SCANNED_FILES = tuple(
    sorted(
        path
        for path in _PACKAGES_ROOT.rglob("*.py")
        if "tests" not in path.parts and "__pycache__" not in path.parts
    )
)

# ``client.py`` constructs the configured client.  ``ingest_cli.py`` is the
# standalone ingest/worker plane: it must create short-lived clients because it
# runs outside the MCP server process.  In ``server.py`` the one allowed call is
# the cache/health chokepoint; all MCP tool implementations must call _get_os().
_INGEST_CLI = "opensearch-mcp/src/opensearch_mcp/ingest_cli.py"
_SERVER = "opensearch-mcp/src/opensearch_mcp/server.py"
_CLIENT_FACTORY = "opensearch-mcp/src/opensearch_mcp/client.py"
_ALLOWED_GET_CLIENT_FILES = {_INGEST_CLI}
_ALLOWED_GET_CLIENT_CALLS = {(_SERVER, "_get_os")}
_ALLOWED_OPEN_SEARCH_CONSTRUCTORS = {(_CLIENT_FACTORY, "get_client")}


def _called_name(call: ast.Call) -> str | None:
    if isinstance(call.func, ast.Name):
        return call.func.id
    if isinstance(call.func, ast.Attribute):
        return call.func.attr
    return None


def _raw_client_sites(source: str, filename: str) -> set[tuple[str, str, str]]:
    """Return raw-client calls, retaining their enclosing function for review."""
    sites: set[tuple[str, str, str]] = set()

    def walk(node: ast.AST, enclosing: str = "<module>") -> None:
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                walk(child, child.name)
                continue
            if isinstance(child, ast.Call):
                called = _called_name(child)
                if called in {"get_client", "OpenSearch"}:
                    sites.add((filename, enclosing, called))
            walk(child, enclosing)

    walk(ast.parse(source, filename=filename))
    return sites


def _unexpected_raw_client_sites() -> set[tuple[str, str, str]]:
    unexpected: set[tuple[str, str, str]] = set()
    for path in _SCANNED_FILES:
        filename = str(path.relative_to(_PACKAGES_ROOT))
        sites = _raw_client_sites(path.read_text(encoding="utf-8"), filename)
        for site in sites:
            _, enclosing, called = site
            if (
                called == "get_client"
                and filename not in _ALLOWED_GET_CLIENT_FILES
                and (filename, enclosing) not in _ALLOWED_GET_CLIENT_CALLS
            ):
                unexpected.add(site)
            if (
                called == "OpenSearch"
                and (filename, enclosing) not in _ALLOWED_OPEN_SEARCH_CONSTRUCTORS
            ):
                unexpected.add(site)
    return unexpected


def test_raw_opensearch_client_access_has_only_explicit_exceptions() -> None:
    """Fail when an MCP-facing path bypasses the cached client chokepoint."""
    assert not _unexpected_raw_client_sites(), (
        "Raw OpenSearch client creation is limited to the factory, standalone "
        "ingest CLI, and server._get_os(). Route MCP tools/resources through "
        f"server._get_os() instead: {sorted(_unexpected_raw_client_sites())}"
    )


def test_raw_client_guard_rejects_a_deliberate_resource_revert() -> None:
    """The guard itself must reject the shortcut this ticket is preventing."""
    source = """
async def opensearch_field_catalog_resource():
    return get_client()
"""
    assert _raw_client_sites(source, "opensearch-mcp/src/opensearch_mcp/registry.py") == {
        (
            "opensearch-mcp/src/opensearch_mcp/registry.py",
            "opensearch_field_catalog_resource",
            "get_client",
        )
    }
    assert (
        ("opensearch-mcp/src/opensearch_mcp/registry.py", "opensearch_field_catalog_resource")
        not in _ALLOWED_GET_CLIENT_CALLS
    )
