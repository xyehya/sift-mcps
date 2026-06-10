from __future__ import annotations

from unittest.mock import MagicMock, patch

from fastmcp import FastMCP
from fastmcp.server import create_proxy
from sift_gateway.active_case import ActiveCase, ActiveCaseError
from sift_gateway.auth import AuthMiddleware
from sift_gateway.identity import Identity
from sift_gateway.policy_middleware import gateway_policy_middlewares
from sift_gateway.rest import rest_routes
from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.testclient import TestClient


def _identity() -> Identity:
    return Identity(
        principal="agent-1",
        principal_type="agent",
        token_id="agent-1",
        agent_id="agent-1",
        created_by=None,
        role="agent",
        source_ip="127.0.0.1",
        auth_surface="mcp",
        case_id="11111111-1111-1111-1111-111111111111",
        tool_scopes=frozenset({"mcp:*"}),
        principal_id="agent-1",
    )


def _case(tmp_path) -> ActiveCase:
    return ActiveCase(
        case_id="11111111-1111-1111-1111-111111111111",
        case_key="db-case",
        title="DB Case",
        description=None,
        status="active",
        artifact_path=str(tmp_path),
        metadata={},
        membership_role="agent",
    )


class _Service:
    def __init__(self, case):
        self.case = case

    def require_active_case_for_principal(self, principal):
        assert principal is not None
        return self.case


class _Gateway:
    def __init__(self, case, safe_args, *, local_tools=None):
        self.active_case_service = _Service(case)
        self._audit = MagicMock()
        self._audit.log = MagicMock(return_value="aid-1")
        self._tool_map = {"addon_needs_case": "addon", "addon_implicit": "addon",
                          "addon_no_case_arg": "addon"}
        self._safe_args = safe_args
        self._gateway_local_tools = set(local_tools or ())

    def is_case_scoped_tool(self, name):
        return name.startswith("addon_") or name in self._gateway_local_tools

    def safe_case_argument_names(self, name):
        # OS2: return None when the tool is absent from the map (unknown → deny).
        # Callers may pass None explicitly to test the deny path, or a set
        # (possibly empty) to test the injection / pass-through paths.
        result = self._safe_args.get(name, "ABSENT")
        if result == "ABSENT":
            return None
        return set(result) if result is not None else None


async def test_proxied_case_tool_receives_db_case_id(tmp_path):
    seen = {}
    child = FastMCP("child")

    @child.tool(name="needs_case")
    async def needs_case(case_id: str = ""):
        seen["case_id"] = case_id
        return {"case_id": case_id}

    gw = _Gateway(_case(tmp_path), {"addon_needs_case": {"case_id"}})
    parent = FastMCP("parent", middleware=gateway_policy_middlewares(gw))
    parent.mount(create_proxy(child), namespace="addon")

    with patch("sift_gateway.policy_middleware.current_mcp_identity", return_value=_identity()), patch(
        "sift_gateway.policy_middleware.check_evidence_gate",
        return_value={"blocked": False, "status": "ok", "issues": [], "manifest_version": 1},
    ):
        result = await parent.call_tool("addon_needs_case", {})

    assert not result.is_error
    assert seen["case_id"] == "11111111-1111-1111-1111-111111111111"


async def test_proxied_case_tool_without_safe_case_arg_is_denied(tmp_path):
    """OS2: safe_case_argument_names returning None (unknown) must deny fail-closed."""
    ran = False
    child = FastMCP("child")

    @child.tool(name="implicit")
    async def implicit():
        nonlocal ran
        ran = True
        return "ran"

    # None signals "unknown" → deny. This is the pre-OS2 behaviour for tools
    # whose manifest does not declare safe_case_argument_names.
    gw = _Gateway(_case(tmp_path), {"addon_implicit": None})
    parent = FastMCP("parent", middleware=gateway_policy_middlewares(gw))
    parent.mount(create_proxy(child), namespace="addon")

    with patch("sift_gateway.policy_middleware.current_mcp_identity", return_value=_identity()):
        result = await parent.call_tool("addon_implicit", {})

    assert ran is False
    assert result.is_error
    assert "active_case_proxy_denied" in result.content[0].text
    sources = [call.kwargs["source"] for call in gw._audit.log.call_args_list]
    assert "gateway_proxy_active_case" in sources
    assert "gateway_mcp_envelope" in sources


async def test_gateway_local_case_tool_without_safe_case_arg_is_not_proxy_denied(tmp_path):
    ran = False
    gw = _Gateway(_case(tmp_path), {"rag_search_case": set()}, local_tools={"rag_search_case"})
    parent = FastMCP("parent", middleware=gateway_policy_middlewares(gw))

    @parent.tool(name="rag_search_case")
    async def rag_search_case():
        nonlocal ran
        ran = True
        return {"status": "ok"}

    with patch("sift_gateway.policy_middleware.current_mcp_identity", return_value=_identity()), patch(
        "sift_gateway.policy_middleware.check_evidence_gate",
        return_value={"blocked": False, "status": "ok", "issues": [], "manifest_version": 1},
    ):
        result = await parent.call_tool("rag_search_case", {})

    assert ran is True
    assert not result.is_error
    assert "active_case_proxy_denied" not in result.content[0].text


async def test_client_supplied_mismatched_case_id_is_rejected(tmp_path):
    ran = False
    child = FastMCP("child")

    @child.tool(name="needs_case")
    async def needs_case(case_id: str = ""):
        nonlocal ran
        ran = True
        return {"case_id": case_id}

    gw = _Gateway(_case(tmp_path), {"addon_needs_case": {"case_id"}})
    parent = FastMCP("parent", middleware=gateway_policy_middlewares(gw))
    parent.mount(create_proxy(child), namespace="addon")

    with patch("sift_gateway.policy_middleware.current_mcp_identity", return_value=_identity()):
        result = await parent.call_tool("addon_needs_case", {"case_id": "other"})

    assert ran is False
    assert result.is_error
    assert "active_case_mismatch" in result.content[0].text


def test_rest_tool_call_maps_active_case_denial_without_exception_detail():
    class Gateway:
        _tool_map = {}

        async def call_tool(self, *args, **kwargs):
            raise ActiveCaseError("active_case_membership_required", http_status=403)

    app = Starlette(
        routes=rest_routes(),
        middleware=[Middleware(AuthMiddleware, api_keys={})],
    )
    app.state.gateway = Gateway()
    client = TestClient(app)

    response = client.post("/api/v1/tools/case_info", json={"arguments": {}})

    assert response.status_code == 403
    payload = response.json()
    assert payload == {"error": "active_case_membership_required", "tool": "case_info"}
    assert "detail" not in payload


# ---------------------------------------------------------------------------
# OS2: manifest-declared safe_case_argument_names injection / mismatch-denial
# ---------------------------------------------------------------------------


async def test_os2_db_case_id_injected_for_manifest_declared_opensearch_tool(tmp_path):
    """OS2 (a): DB active case_id is injected when manifest declares safe_case_argument_names."""
    seen = {}
    child = FastMCP("child")

    @child.tool(name="search")
    async def opensearch_search(case_id: str = "", query: str = "*"):
        seen["case_id"] = case_id
        seen["query"] = query
        return {"results": [], "total": 0}

    # Simulates an OpenSearch tool whose manifest declared safe_case_argument_names: ["case_id"]
    gw = _Gateway(_case(tmp_path), {"addon_search": {"case_id"}})
    parent = FastMCP("parent", middleware=gateway_policy_middlewares(gw))
    parent.mount(create_proxy(child), namespace="addon")

    with patch("sift_gateway.policy_middleware.current_mcp_identity", return_value=_identity()), patch(
        "sift_gateway.policy_middleware.check_evidence_gate",
        return_value={"blocked": False, "status": "ok", "issues": [], "manifest_version": 1},
    ):
        result = await parent.call_tool("addon_search", {"query": "event.code:4624"})

    assert not result.is_error, result.content[0].text
    # Gateway must have injected the DB case_id, not left it empty.
    assert seen["case_id"] == "11111111-1111-1111-1111-111111111111"
    assert seen["query"] == "event.code:4624"


async def test_os2_explicit_mismatched_case_id_is_denied_before_backend_dispatch(tmp_path):
    """OS2 (b): Client-supplied case_id that differs from DB active case is denied before dispatch."""
    ran = False
    child = FastMCP("child")

    @child.tool(name="search")
    async def opensearch_search(case_id: str = "", query: str = "*"):
        nonlocal ran
        ran = True
        return {"results": []}

    gw = _Gateway(_case(tmp_path), {"addon_search": {"case_id"}})
    parent = FastMCP("parent", middleware=gateway_policy_middlewares(gw))
    parent.mount(create_proxy(child), namespace="addon")

    with patch("sift_gateway.policy_middleware.current_mcp_identity", return_value=_identity()):
        result = await parent.call_tool(
            "addon_search",
            {"case_id": "aaaaaaaa-0000-0000-0000-000000000000", "query": "*"},
        )

    # Backend must NOT have been called — denial happens before dispatch.
    assert ran is False
    assert result.is_error
    assert "active_case_mismatch" in result.content[0].text


async def test_os2_manifest_empty_safe_args_passes_through_without_denial(tmp_path):
    """OS2 (a): Case-scoped tools with empty safe_case_argument_names pass through without injection."""
    ran = False
    child = FastMCP("child")

    @child.tool(name="status")
    async def opensearch_status():
        nonlocal ran
        ran = True
        return {"cluster_status": "green", "indices": []}

    # Manifest declares safe_case_argument_names: [] — case-scoped but no injection arg.
    gw = _Gateway(_case(tmp_path), {"addon_status": set()})
    parent = FastMCP("parent", middleware=gateway_policy_middlewares(gw))
    parent.mount(create_proxy(child), namespace="addon")

    with patch("sift_gateway.policy_middleware.current_mcp_identity", return_value=_identity()), patch(
        "sift_gateway.policy_middleware.check_evidence_gate",
        return_value={"blocked": False, "status": "ok", "issues": [], "manifest_version": 1},
    ):
        result = await parent.call_tool("addon_status", {})

    assert ran is True, "Backend must be reached — manifest declares no injection arg"
    assert not result.is_error
    assert "active_case_proxy_denied" not in result.content[0].text


async def test_os2_non_opensearch_tool_not_widened(tmp_path):
    """OS2 (c): A non-OpenSearch add-on tool without manifest declaration is still denied fail-closed."""
    ran = False
    child = FastMCP("child")

    @child.tool(name="run_shell")
    async def run_shell(cmd: str = ""):
        nonlocal ran
        ran = True
        return {"output": "hacked"}

    # No manifest entry (ABSENT key) → returns None → deny.
    gw = _Gateway(_case(tmp_path), {})  # empty dict: every tool returns None
    # Make run_shell appear case-scoped so the middleware evaluates it.
    gw._tool_map["addon_run_shell"] = "addon"
    parent = FastMCP("parent", middleware=gateway_policy_middlewares(gw))
    parent.mount(create_proxy(child), namespace="addon")

    with patch("sift_gateway.policy_middleware.current_mcp_identity", return_value=_identity()):
        result = await parent.call_tool("addon_run_shell", {"cmd": "id"})

    assert ran is False
    assert result.is_error
    assert "active_case_proxy_denied" in result.content[0].text


async def test_os2_matching_case_id_not_double_denied(tmp_path):
    """OS2: A client-supplied case_id that MATCHES the DB active case is accepted (not denied)."""
    seen = {}
    child = FastMCP("child")

    @child.tool(name="count")
    async def opensearch_count(case_id: str = "", query: str = "*"):
        seen["case_id"] = case_id
        return {"count": 42}

    gw = _Gateway(_case(tmp_path), {"addon_count": {"case_id"}})
    parent = FastMCP("parent", middleware=gateway_policy_middlewares(gw))
    parent.mount(create_proxy(child), namespace="addon")

    with patch("sift_gateway.policy_middleware.current_mcp_identity", return_value=_identity()), patch(
        "sift_gateway.policy_middleware.check_evidence_gate",
        return_value={"blocked": False, "status": "ok", "issues": [], "manifest_version": 1},
    ):
        # Supply the CORRECT case_id — should be accepted.
        result = await parent.call_tool(
            "addon_count",
            {"case_id": "11111111-1111-1111-1111-111111111111", "query": "*"},
        )

    assert not result.is_error, result.content[0].text
    assert seen["case_id"] == "11111111-1111-1111-1111-111111111111"
