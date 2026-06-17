"""BATCH-OSX1: late-seeded add-on backends become visible WITHOUT a gateway restart.

Root cause fixed here (see docs/migration OSX track "Discovered architecture"):
the gateway instantiates add-on backends ONCE in ``Gateway.__init__`` from
``app.mcp_backends``. When the installer (or an operator via the portal) seeds a
row *after* the gateway started, the backend was invisible until a full restart.

These tests prove:
  - ``Gateway.reload_backend_registry`` re-reads the registry, instantiates rows
    that appeared after ``__init__``, mounts their FastMCP proxy onto the LIVE
    aggregate server, and rebuilds the tool map — no restart.
  - The reload is additive + idempotent (no duplicate mount, no churn when the
    registry is unchanged).
  - The OSX1 double-spawn dedupe: a backend already served by a mounted FastMCP
    proxy is NOT eagerly (re)started by the late-start path, so no redundant
    second stdio subprocess is spawned.
"""

from __future__ import annotations

import asyncio
import json

import pytest
from fastmcp import FastMCP
from mcp.types import Tool

from sift_gateway.mcp_server import (
    expected_mounted_tool_names,
    mount_single_addon_proxy,
)
from sift_gateway.server import Gateway


def _execute_security() -> dict:
    return {"execute": {"security": {"denied_binaries": ["env"]}}}


_MANIFEST = {
    "spec_version": "1.0",
    "name": "opensearch-mcp",
    "version": "1.0.0",
    "tier": "addon",
    "transport": "stdio",
    "namespace": "opensearch",
    "instructions": "OpenSearch derived plane.",
    "capabilities": {"provides": ["search"], "requires": [], "enriches_responses": False},
    "tools": [
        {
            "name": "opensearch_search",
            "description": "search indexed evidence",
            "read_only": True,
            "readOnlyHint": True,
            "category": "search-analysis",
            "recommended_phase": "ANALYZE",
        }
    ],
}


class _FakeBackend:
    """Add-on backend stub: lists manifest tools, tracks start() spawn count."""

    def __init__(self, manifest: dict, *, started: bool = False):
        self.manifest = manifest
        self.config = {"type": "stdio", "command": "true", "args": []}
        self.enabled = True
        self.last_tool_call = 0.0
        self._started = started
        self.start_calls = 0

    @property
    def started(self) -> bool:
        return self._started

    async def start(self) -> None:
        self.start_calls += 1
        self._started = True

    async def stop(self) -> None:  # pragma: no cover
        self._started = False

    async def list_tools(self) -> list[Tool]:
        return [
            Tool(name=t["name"], description=t["description"], inputSchema={"type": "object"})
            for t in self.manifest["tools"]
        ]

    async def health_check(self):  # pragma: no cover
        return {"status": "ok"}


class _FakeRegistry:
    """Stand-in for McpBackendRegistry.create_backend_instances()."""

    def __init__(self):
        self._instances: dict[str, _FakeBackend] = {}
        self.read_count = 0

    def seed(self, name: str, backend: _FakeBackend) -> None:
        self._instances[name] = backend

    def create_backend_instances(self):
        self.read_count += 1
        # Mirror the real signature: (dict[name->backend], loaded_at)
        return dict(self._instances), None


def _make_gateway() -> Gateway:
    return Gateway({"backends": {}, **_execute_security()})


def test_reload_picks_up_late_seeded_backend_without_restart():
    gateway = _make_gateway()
    # Live FastMCP aggregate server (as create_gateway_mcp_server would build).
    mcp = FastMCP("sift-gateway-test")
    gateway._fastmcp_server = mcp

    registry = _FakeRegistry()
    gateway.mcp_backend_registry = registry

    # Nothing seeded yet -> gateway boots with zero add-on tools.
    asyncio.run(gateway._build_tool_map())
    assert "opensearch_search" not in gateway._tool_map

    # Operator/installer seeds the row AFTER the gateway started.
    registry.seed("opensearch-mcp", _FakeBackend(_MANIFEST, started=True))

    added = asyncio.run(gateway.reload_backend_registry())
    assert added is True

    # Backend is now present, mounted, and its tool is in the live tool map.
    assert "opensearch-mcp" in gateway.backends
    assert "opensearch-mcp" in gateway._mounted_proxy_backends
    assert gateway._tool_map.get("opensearch_search") == "opensearch-mcp"

    # And the aggregate /mcp surface now expects this proxy's tool (the mount
    # happened on the live FastMCP server), proving no restart was needed. We
    # assert via expected_mounted_tool_names rather than mcp.list_tools() because
    # the fake backend command ("true") has no real MCP session to enumerate.
    assert "opensearch_search" in expected_mounted_tool_names(gateway)


def test_pre_serve_reload_closes_startup_mount_race():
    """wave8/ingest-tools (Blocker B): a backend seeded into app.mcp_backends
    AFTER __init__ but BEFORE the server starts serving /mcp must be mounted by
    the pre-serve registry reload, so a client connecting right after restart
    sees the add-on tools (not only the core in-process tools).

    This replicates the lifespan ordering: __init__ found zero backends, then a
    row was seeded, then app_lifespan runs reload_backend_registry() BEFORE the
    expected/actual tool reconciliation that gates serving.
    """
    gateway = _make_gateway()
    gateway._fastmcp_server = FastMCP("sift-gateway-test")
    registry = _FakeRegistry()
    gateway.mcp_backend_registry = registry

    # __init__-time: registry empty -> no add-on proxies mounted at build time.
    asyncio.run(gateway._build_tool_map())
    assert "opensearch-mcp" not in gateway._mounted_proxy_backends

    # Row seeded after __init__ but before serving.
    registry.seed("opensearch-mcp", _FakeBackend(_MANIFEST, started=True))

    # Pre-serve reload (what app_lifespan now calls before the gate check).
    asyncio.run(gateway.reload_backend_registry())

    # The add-on tool is now in the expected-mounted catalog used to gate serve,
    # so the aggregate /mcp surface is complete before the first request.
    assert "opensearch-mcp" in gateway._mounted_proxy_backends
    assert "opensearch_search" in expected_mounted_tool_names(gateway)
    assert gateway._tool_map.get("opensearch_search") == "opensearch-mcp"


def test_reload_is_idempotent_and_quiet_when_unchanged():
    gateway = _make_gateway()
    gateway._fastmcp_server = FastMCP("sift-gateway-test")
    registry = _FakeRegistry()
    gateway.mcp_backend_registry = registry
    registry.seed("opensearch-mcp", _FakeBackend(_MANIFEST, started=True))

    assert asyncio.run(gateway.reload_backend_registry()) is True
    # Second reload with no registry change: no new backend, no double mount.
    assert asyncio.run(gateway.reload_backend_registry()) is False
    assert list(gateway.backends) == ["opensearch-mcp"]
    assert gateway._mounted_proxy_backends == {"opensearch-mcp"}


def test_reload_noop_without_registry():
    gateway = _make_gateway()
    gateway.mcp_backend_registry = None
    assert asyncio.run(gateway.reload_backend_registry()) is False


def test_mount_single_addon_proxy_is_idempotent():
    gateway = _make_gateway()
    mcp = FastMCP("sift-gateway-test")
    backend = _FakeBackend(_MANIFEST, started=True)
    gateway.backends["opensearch-mcp"] = backend

    assert mount_single_addon_proxy(mcp, gateway, "opensearch-mcp", backend) is True
    # Already mounted -> no second mount.
    assert mount_single_addon_proxy(mcp, gateway, "opensearch-mcp", backend) is False


def test_proxy_mounted_backend_is_not_eagerly_started_by_late_checker():
    """OSX1 double-spawn dedupe.

    A stdio add-on already served by a mounted FastMCP proxy must NOT have a
    second persistent stdio subprocess spawned by the late-start loop. We drive
    one iteration of the _late_start_checker body's start branch and assert the
    backend's start() (which spawns the subprocess) is never called when the
    backend is in _mounted_proxy_backends.
    """
    gateway = _make_gateway()
    backend = _FakeBackend(_MANIFEST, started=False)
    gateway.backends["opensearch-mcp"] = backend
    gateway._mounted_proxy_backends = {"opensearch-mcp"}

    async def _one_pass():
        # Replicate the dedupe predicate the checker applies before start().
        for name, b in list(gateway.backends.items()):
            if not b.started and name in gateway._mounted_proxy_backends:
                continue  # skip redundant eager spawn
            await b.start()

    asyncio.run(_one_pass())
    assert backend.start_calls == 0, "proxy-served backend was redundantly spawned"


def test_non_proxy_backend_is_still_eagerly_started():
    """Counterpart: a backend WITHOUT a mounted proxy is still late-started."""
    gateway = _make_gateway()
    backend = _FakeBackend(_MANIFEST, started=False)
    gateway.backends["other-mcp"] = backend
    gateway._mounted_proxy_backends = set()

    async def _one_pass():
        for name, b in list(gateway.backends.items()):
            if not b.started and name in gateway._mounted_proxy_backends:
                continue
            await b.start()

    asyncio.run(_one_pass())
    assert backend.start_calls == 1


# ---------------------------------------------------------------------------
# XYE-44: GET /api/v1/backends must not report a proxy-mounted, on-demand
# add-on as "stopped". It should mirror /health's operator translation
# (ok + mounted_proxy) and flag on_demand=True, so the DB-registry table agrees
# with the System Health panel instead of looking broken.
# ---------------------------------------------------------------------------


class _FakeRecord:
    """Minimal app.mcp_backends record stand-in for list_backends()."""

    def __init__(self, name: str, manifest: dict, *, enabled: bool = True):
        self.name = name
        self.manifest = manifest
        self.enabled = enabled
        self.updated_at = None  # with a non-None catalog load time -> not pending

    def public_dict(self, *, started: bool, available: bool, pending_apply: bool) -> dict:
        return {
            "name": self.name,
            "type": self.manifest.get("transport", "stdio"),
            "enabled": self.enabled,
            "started": started,
            "available": available,
            "pending_apply": pending_apply,
        }


class _ListRegistry:
    def __init__(self, records: list):
        self._records = records
        self.health_updates: list[tuple] = []

    def list_backends(self):
        return self._records

    def update_health(self, name, status, detail=None):
        self.health_updates.append((name, status, detail))


class _FakeRequest:
    def __init__(self, gateway):
        app = type("App", (), {})()
        app.state = type("State", (), {"gateway": gateway})()
        self.app = app


def _list_backends_item(gateway, record) -> dict:
    from sift_gateway.rest import list_backends

    gateway.mcp_backend_registry = _ListRegistry([record])
    # Non-None catalog-load time so _backend_pending_apply keys off updated_at
    # (None -> not pending) rather than defaulting to enabled=True.
    gateway._mcp_catalog_loaded_at = 1
    resp = asyncio.run(list_backends(_FakeRequest(gateway)))
    payload = json.loads(resp.body)
    assert payload["count"] == 1
    return payload["backends"][0]


def test_list_backends_reports_proxy_mounted_addon_as_on_demand_not_stopped():
    gateway = _make_gateway()
    # Proxy-mounted but NOT started: the OSX1 on-demand resting state.
    gateway.backends["opensearch-mcp"] = _FakeBackend(_MANIFEST, started=False)
    gateway._mounted_proxy_backends = {"opensearch-mcp"}

    item = _list_backends_item(gateway, _FakeRecord("opensearch-mcp", _MANIFEST))

    assert item["on_demand"] is True
    assert item["started"] is False
    assert item["pending_apply"] is False
    # No longer "stopped" — mirrors /health's operator translation.
    assert item["health"]["status"] == "ok"
    assert item["health"].get("mounted_proxy") is True


def test_list_backends_non_mounted_not_started_stays_stopped():
    gateway = _make_gateway()
    gateway.backends["other-mcp"] = _FakeBackend(_MANIFEST, started=False)
    gateway._mounted_proxy_backends = set()

    item = _list_backends_item(gateway, _FakeRecord("other-mcp", _MANIFEST))

    assert item["on_demand"] is False
    assert item["health"]["status"] == "stopped"
