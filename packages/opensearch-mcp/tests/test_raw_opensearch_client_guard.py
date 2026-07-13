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
_CASE_ID_BACKFILL = "opensearch-mcp/src/opensearch_mcp/case_id_backfill.py"
_ALLOWED_GET_CLIENT_FILES = {_INGEST_CLI}
# ``case_id_backfill.main`` is an operator-only derived-index maintenance CLI,
# deliberately outside the MCP surface.  Keep this function-level exception
# narrow so any future client creation in that module remains reviewable.
_ALLOWED_GET_CLIENT_CALLS = {(_SERVER, "_get_os"), (_CASE_ID_BACKFILL, "main")}
_ALLOWED_OPEN_SEARCH_CONSTRUCTORS = {(_CLIENT_FACTORY, "get_client")}


def _called_name(call: ast.Call) -> str | None:
    if isinstance(call.func, ast.Name):
        return call.func.id
    if isinstance(call.func, ast.Attribute):
        return call.func.attr
    return None


def _factory_aliases(tree: ast.AST) -> tuple[set[str], set[str]]:
    """Resolve direct-import aliases for the two OpenSearch factory symbols."""
    get_client_aliases = {"get_client"}
    constructor_aliases = {"OpenSearch"}
    for node in ast.walk(tree):
        if not isinstance(node, ast.ImportFrom):
            continue
        if node.module == "opensearch_mcp.client":
            get_client_aliases.update(
                alias.asname or alias.name for alias in node.names if alias.name == "get_client"
            )
        if node.module == "opensearchpy":
            constructor_aliases.update(
                alias.asname or alias.name for alias in node.names if alias.name == "OpenSearch"
            )
    return get_client_aliases, constructor_aliases


def _raw_client_sites(source: str, filename: str) -> set[tuple[str, str, str]]:
    """Return raw-client calls, retaining their enclosing function for review."""
    tree = ast.parse(source, filename=filename)
    get_client_aliases, constructor_aliases = _factory_aliases(tree)
    sites: set[tuple[str, str, str]] = set()

    def walk(node: ast.AST, enclosing: str = "<module>") -> None:
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                walk(child, child.name)
                continue
            if isinstance(child, ast.Call):
                called = _called_name(child)
                if called in get_client_aliases:
                    sites.add((filename, enclosing, "get_client"))
                elif called in constructor_aliases:
                    sites.add((filename, enclosing, "OpenSearch"))
                elif called == "_get_os":
                    sites.add((filename, enclosing, "_get_os"))
            walk(child, enclosing)

    walk(tree)
    return sites


def _is_approved_raw_client_site(site: tuple[str, str, str]) -> bool:
    filename, enclosing, called = site
    if called == "get_client":
        return (
            filename in _ALLOWED_GET_CLIENT_FILES
            or (filename, enclosing) in _ALLOWED_GET_CLIENT_CALLS
        )
    if called == "OpenSearch":
        return (filename, enclosing) in _ALLOWED_OPEN_SEARCH_CONSTRUCTORS
    if called == "_get_os":
        return filename == _SERVER
    return False


def _unexpected_raw_client_sites() -> set[tuple[str, str, str]]:
    unexpected: set[tuple[str, str, str]] = set()
    for path in _SCANNED_FILES:
        filename = str(path.relative_to(_PACKAGES_ROOT))
        sites = _raw_client_sites(path.read_text(encoding="utf-8"), filename)
        for site in sites:
            if not _is_approved_raw_client_site(site):
                unexpected.add(site)
    return unexpected


def test_raw_opensearch_client_access_has_only_explicit_exceptions() -> None:
    """Fail when an MCP-facing path bypasses the cached client chokepoint."""
    assert not _unexpected_raw_client_sites(), (
        "Raw OpenSearch client creation is limited to the factory, standalone "
        "ingest CLI, and server._get_os(). Route MCP tools/resources through "
        f"server._get_os() instead: {sorted(_unexpected_raw_client_sites())}"
    )


def test_raw_client_guard_rejects_alias_and_client_reach_through_reverts() -> None:
    """The guard must reject aliases and resource-level client reach-through."""
    source = """
from opensearch_mcp.client import get_client as raw_client

async def opensearch_field_catalog_resource():
    return raw_client()
"""
    assert _raw_client_sites(source, "opensearch-mcp/src/opensearch_mcp/registry.py") == {
        (
            "opensearch-mcp/src/opensearch_mcp/registry.py",
            "opensearch_field_catalog_resource",
            "get_client",
        )
    }
    assert not _is_approved_raw_client_site(
        (
            "opensearch-mcp/src/opensearch_mcp/registry.py",
            "opensearch_field_catalog_resource",
            "get_client",
        )
    )
    reach_through = """
async def opensearch_field_catalog_resource():
    return _get_os().search(index='case-*')
"""
    assert _raw_client_sites(
        reach_through, "opensearch-mcp/src/opensearch_mcp/registry.py"
    ) == {
        (
            "opensearch-mcp/src/opensearch_mcp/registry.py",
            "opensearch_field_catalog_resource",
            "_get_os",
        )
    }
    assert not _is_approved_raw_client_site(
        (
            "opensearch-mcp/src/opensearch_mcp/registry.py",
            "opensearch_field_catalog_resource",
            "_get_os",
        )
    )
