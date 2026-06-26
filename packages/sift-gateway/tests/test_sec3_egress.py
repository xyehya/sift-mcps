"""SEC-3 — shared egress policy (anti-SSRF / anti-DNS-rebinding) + DSS-CAN-019.

Fail-on-revert tests: each asserts a denial that only holds while the fix is in
place. Reverting the pin (the URL-rewrite-to-pinned-IP in
``_PinnedEgressTransport``) breaks the pinning tests; reverting the per-connect
``validate_egress_url`` call in ``HttpMCPBackend.start`` breaks the
connect-time/rebinding tests; reverting the join host-binding breaks the
DSS-CAN-019 tests.
"""

from __future__ import annotations

from types import SimpleNamespace

import httpx
import pytest
import sift_gateway.backends.egress as egress
import sift_gateway.backends.http_backend as hb
import sift_gateway.join as join_mod
import sift_gateway.rest as rest
from sift_gateway.backends.egress import (
    EgressTarget,
    _PinnedEgressTransport,
    make_pinned_egress_factory,
    validate_egress_url,
)
from sift_gateway.backends.http_backend import HttpMCPBackend
from sift_gateway.rest import register_backend_logic, rest_routes
from starlette.applications import Starlette
from starlette.testclient import TestClient

pytestmark = pytest.mark.anyio


@pytest.fixture
def anyio_backend():
    return "asyncio"


def _addr(ip: str, port: int = 443):
    """getaddrinfo-shaped tuple list for a single address."""
    family = 10 if ":" in ip else 2  # AF_INET6 / AF_INET
    return [(family, 1, 6, "", (ip, port))]


# --------------------------------------------------------------------------- #
# IP classification / validator
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "url",
    [
        "https://[::1]/mcp",
        "https://[fc00::1]/mcp",  # IPv6 unique-local
        "https://[fe80::1]/mcp",  # IPv6 link-local
        "http://[::ffff:10.0.0.1]/",  # IPv4-mapped private
        "http://0.0.0.0/",
        "http://[::]/",
        "http://127.0.0.1:9000/mcp",
        "http://169.254.169.254/latest/meta-data",  # cloud metadata
    ],
)
def test_validate_rejects_literal_internal_addresses(url):
    with pytest.raises(ValueError, match="blocked private/link-local"):
        validate_egress_url(url, label="t")


def test_validate_rejects_non_http_scheme_and_userinfo():
    with pytest.raises(ValueError, match="http"):
        validate_egress_url("ftp://example.com/x", label="t")
    with pytest.raises(ValueError, match="credentials"):
        validate_egress_url("https://user:pw@example.com/x", label="t")


def test_validate_blocks_private_dns_resolution(monkeypatch):
    monkeypatch.setattr(egress.socket, "getaddrinfo", lambda *a, **k: _addr("10.9.8.7"))
    with pytest.raises(ValueError, match="blocked private/link-local"):
        validate_egress_url("https://internal.example/mcp", label="t")


def test_validate_dual_stack_rejects_if_any_address_internal(monkeypatch):
    # A rebinder can return both a public and a private record; any bad one fails.
    infos = _addr("203.0.113.5") + _addr("10.0.0.1")
    monkeypatch.setattr(egress.socket, "getaddrinfo", lambda *a, **k: infos)
    with pytest.raises(ValueError, match="blocked private/link-local"):
        validate_egress_url("https://mixed.example/mcp", label="t")


def test_validate_returns_pinned_public_ips(monkeypatch):
    monkeypatch.setattr(egress.socket, "getaddrinfo", lambda *a, **k: _addr("8.8.8.8"))
    target = validate_egress_url("https://good.example/mcp", label="t")
    assert target.hostname == "good.example"
    assert target.pinned_ips == ("8.8.8.8",)


def test_validate_env_allowlist_permits_internal_host(monkeypatch):
    monkeypatch.setattr(egress.socket, "getaddrinfo", lambda *a, **k: _addr("192.168.50.10"))
    # Default fail-closed: blocked.
    with pytest.raises(ValueError):
        validate_egress_url("https://winbox.lan/mcp", label="t")
    # Operator opt-in unblocks exactly this host.
    monkeypatch.setenv("SIFT_EGRESS_ALLOWED_HOSTS", "winbox.lan")
    target = validate_egress_url("https://winbox.lan/mcp", label="t")
    assert target.pinned_ips == ("192.168.50.10",)


def test_validate_env_allowlist_cidr(monkeypatch):
    monkeypatch.setattr(egress.socket, "getaddrinfo", lambda *a, **k: _addr("10.20.30.40"))
    monkeypatch.setenv("SIFT_EGRESS_ALLOWED_CIDRS", "10.20.0.0/16")
    target = validate_egress_url("https://lab.internal/mcp", label="t")
    assert target.pinned_ips == ("10.20.30.40",)


# --------------------------------------------------------------------------- #
# Pinning transport: dials the pinned IP, keeps TLS hostname (SNI) + Host
# --------------------------------------------------------------------------- #


class _RecordingInner(httpx.AsyncBaseTransport):
    def __init__(self):
        self.seen: httpx.Request | None = None

    async def handle_async_request(self, request):
        self.seen = request
        return httpx.Response(200, request=request)


async def test_pinned_transport_dials_pinned_ip_and_preserves_tls_hostname():
    target = EgressTarget("mcp.example.com", 443, "https", ("203.0.113.7",))
    transport = _PinnedEgressTransport(target)
    inner = _RecordingInner()
    transport._inner = inner  # capture what actually gets dialed

    req = httpx.Request("POST", "https://mcp.example.com/mcp", json={"x": 1})
    await transport.handle_async_request(req)

    assert inner.seen is not None
    # Socket targets the pinned IP (the anti-rebinding control)...
    assert inner.seen.url.host == "203.0.113.7"
    # ...while TLS verifies against the original hostname (SNI) and Host is intact.
    assert inner.seen.extensions.get("sni_hostname") == "mcp.example.com"
    assert inner.seen.headers["host"] == "mcp.example.com"


async def test_pinned_transport_refuses_off_target_host():
    target = EgressTarget("good.example", 443, "https", ("203.0.113.7",))
    transport = _PinnedEgressTransport(target)
    transport._inner = _RecordingInner()
    req = httpx.Request("GET", "https://evil.example/")
    with pytest.raises(httpx.RequestError):
        await transport.handle_async_request(req)


def test_pinned_factory_disables_redirects():
    target = EgressTarget("good.example", 443, "https", ("203.0.113.7",))
    client = make_pinned_egress_factory(target)(headers={"a": "b"})
    try:
        # A 30x to an internal address must never be auto-followed.
        assert client.follow_redirects is False
    finally:
        # close without awaiting the network (no connection was opened)
        pass


# --------------------------------------------------------------------------- #
# HttpMCPBackend.start(): connect-time gate + credentials-after-validation
# --------------------------------------------------------------------------- #


async def test_start_denies_private_destination_before_sending_token(monkeypatch):
    """The bearer token is never sent to a private-resolving destination."""
    connected: list = []

    def _must_not_connect(*args, **kwargs):
        connected.append((args, kwargs))
        raise AssertionError("connection attempted to an unvalidated destination")

    monkeypatch.setattr(hb, "streamablehttp_client", _must_not_connect)
    monkeypatch.setattr(egress.socket, "getaddrinfo", lambda *a, **k: _addr("10.1.2.3"))

    backend = HttpMCPBackend(
        "b",
        {"type": "http", "url": "https://winhost.example/mcp", "bearer_token": "SUPERSECRET"},
    )
    with pytest.raises(ValueError, match="blocked private/link-local"):
        await backend.start()
    assert connected == []  # no connect => the Authorization header never left


class _ACM:
    def __init__(self, value):
        self._value = value

    async def __aenter__(self):
        return self._value

    async def __aexit__(self, *exc):
        return False


class _FakeSession:
    async def initialize(self):
        return SimpleNamespace(instructions=None)

    async def list_tools(self):
        return SimpleNamespace(tools=[])


async def test_start_revalidates_on_reconnect_blocks_rebind(monkeypatch):
    """PUBLIC first, PRIVATE second resolution -> the second connect is denied.

    Proves start() (the reconnect path) re-validates each connect, so a host that
    rebinds to a private address between connections cannot be reached.
    """
    resolutions = [_addr("8.8.8.8"), _addr("10.0.0.5")]
    monkeypatch.setattr(
        egress.socket, "getaddrinfo", lambda *a, **k: resolutions.pop(0)
    )

    connects: list = []

    def _fake_streamable(url, **kwargs):
        connects.append(url)
        return _ACM((object(), object(), None))

    monkeypatch.setattr(hb, "streamablehttp_client", _fake_streamable)
    monkeypatch.setattr(hb, "ClientSession", lambda r, w: _ACM(_FakeSession()))

    backend = HttpMCPBackend(
        "b", {"type": "http", "url": "https://flip.example/mcp", "bearer_token": "tok"}
    )
    await backend.start()  # 1st: public -> succeeds
    assert connects == ["https://flip.example/mcp"]

    await backend._teardown()  # simulate a dropped connection -> reconnect
    with pytest.raises(ValueError, match="blocked private/link-local"):
        await backend.start()  # 2nd: private -> denied
    assert len(connects) == 1  # the rebind attempt never reached the network


# --------------------------------------------------------------------------- #
# Persistence (register) gate
# --------------------------------------------------------------------------- #


async def test_register_logic_rejects_private_http_url():
    gateway = SimpleNamespace(mcp_backend_registry=None)
    body = {"name": "evil-http", "config": {"type": "http", "url": "http://127.0.0.1:9000/mcp"}}
    response, status = await register_backend_logic(gateway, body, actor=None)
    assert status == 422
    assert response.get("registered") is False
    reasons = " ".join(r.get("reason", "") for r in response.get("reasons", []))
    assert "blocked private/link-local" in reasons


# --------------------------------------------------------------------------- #
# DSS-CAN-019 — join code bound to expected wintools host
# --------------------------------------------------------------------------- #


@pytest.fixture
def join_state(tmp_path, monkeypatch):
    state_dir = tmp_path / ".sift"
    state_dir.mkdir()
    monkeypatch.setattr(join_mod, "_STATE_DIR", state_dir)
    monkeypatch.setattr(join_mod, "_STATE_FILE", state_dir / ".join_state.json")
    join_mod._join_failures.clear()
    return state_dir


def _join_client() -> TestClient:
    app = Starlette(routes=rest_routes())
    app.state.gateway = SimpleNamespace(mcp_backend_registry=None, backends={}, config={})
    return TestClient(app, raise_server_exceptions=False)


def test_join_wintools_requires_bound_host(join_state):
    code = join_mod.generate_join_code()
    join_mod.store_join_code(code, expires_hours=1)  # no bound host
    client = _join_client()
    resp = client.post(
        "/api/v1/setup/join",
        json={
            "code": code,
            "machine_type": "wintools",
            "wintools_url": "https://winbox.lan/mcp",
            "wintools_token": "t",
        },
    )
    assert resp.status_code == 403
    assert "not bound" in resp.json()["error"]


def test_join_wintools_host_mismatch_rejected(join_state):
    code = join_mod.generate_join_code()
    join_mod.store_join_code(code, expires_hours=1, bound_host="winbox.lan")
    client = _join_client()
    resp = client.post(
        "/api/v1/setup/join",
        json={
            "code": code,
            "machine_type": "wintools",
            "wintools_url": "https://evil.example/mcp",
            "wintools_token": "t",
        },
    )
    assert resp.status_code == 403
    assert "does not match the bound host" in resp.json()["error"]


def test_join_wintools_matching_host_passes_binding_and_egress(join_state, monkeypatch):
    # The bound host resolves to a LAN address; only the DSS-CAN-019 binding
    # authorizes egress to it. A matching join then reaches registration.
    monkeypatch.setattr(egress.socket, "getaddrinfo", lambda *a, **k: _addr("192.168.7.7"))

    captured = {}

    async def _fake_register(gateway, body, *, actor=None, extra_allowed_egress_hosts=frozenset()):
        captured["body"] = body
        captured["allow"] = extra_allowed_egress_hosts
        return {"registered": True, "name": body["name"], "restart_required": True}, 201

    monkeypatch.setattr(rest, "register_backend_logic", _fake_register)

    code = join_mod.generate_join_code()
    join_mod.store_join_code(code, expires_hours=1, bound_host="winbox.lan")
    client = _join_client()
    resp = client.post(
        "/api/v1/setup/join",
        json={
            "code": code,
            "machine_type": "wintools",
            "wintools_url": "https://winbox.lan/mcp",
            "wintools_token": "t",
        },
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body.get("wintools_registered") is True
    # The bound host was threaded into registration as the egress allowance.
    assert "winbox.lan" in captured["allow"]
