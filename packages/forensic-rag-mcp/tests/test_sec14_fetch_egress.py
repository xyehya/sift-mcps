"""SEC-14 — RAG source-fetch egress hardening (resolve-and-pin + no auto-redirect).

These are fail-on-revert tests: they assert the destination IP is classified
(SSRF / DNS-rebinding guard), the socket is pinned to the vetted IP, and
redirects are followed MANUALLY with full revalidation per hop. Reverting the
hardening in ``sources._fetch_url_once`` / ``_resolve_and_pin`` re-greens the
old auto-redirect path and fails these.
"""

from __future__ import annotations

import email.message
import socket

import pytest
from rag_mcp import sources


# ---------------------------------------------------------------------------
# Test doubles
# ---------------------------------------------------------------------------
class _FakeResponse:
    def __init__(self, status, headers=None, body=b"", reason="OK"):
        self.status = status
        self.reason = reason
        self._headers = headers or {}
        self.msg = email.message.Message()
        self._body = body
        self._drained = False

    def getheader(self, name, default=None):
        for key, value in self._headers.items():
            if key.lower() == name.lower():
                return value
        return default

    def read(self, amt=None):
        if self._drained:
            return b""
        self._drained = True
        return self._body


class _FakeConn:
    def __init__(self):
        self.closed = False

    def close(self):
        self.closed = True


def _make_fake_exchange(responses, calls):
    """Return a stand-in for sources._http_exchange that scripts responses."""
    response_iter = iter(responses)

    def _exchange(scheme, hostname, pinned_ip, port, selector, headers, timeout):
        calls.append(
            {
                "scheme": scheme,
                "hostname": hostname,
                "pinned_ip": pinned_ip,
                "port": port,
                "selector": selector,
                "headers": dict(headers),
            }
        )
        return _FakeConn(), next(response_iter)

    return _exchange


def _make_fake_getaddrinfo(host_to_ips):
    def _gai(host, port, *args, **kwargs):
        ips = host_to_ips[host]
        if isinstance(ips, str):
            ips = [ips]
        out = []
        for ip in ips:
            family = socket.AF_INET6 if ":" in ip else socket.AF_INET
            out.append((family, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", (ip, port)))
        return out

    return _gai


PUBLIC_GH_IP = "140.82.112.3"


# ---------------------------------------------------------------------------
# _resolve_and_pin: IP classification (deny non-global by default)
# ---------------------------------------------------------------------------
def test_resolve_and_pin_accepts_public(monkeypatch):
    monkeypatch.setattr(
        sources.socket, "getaddrinfo", _make_fake_getaddrinfo({"x": PUBLIC_GH_IP})
    )
    assert sources._resolve_and_pin("x", 443) == PUBLIC_GH_IP


@pytest.mark.parametrize(
    "bad_ip",
    [
        "10.0.0.5",  # private
        "127.0.0.1",  # loopback
        "169.254.169.254",  # link-local (cloud metadata)
        "100.64.0.1",  # CGNAT — is_private=False but not is_global
        "198.18.0.1",  # benchmarking — caught by not is_global
        "::ffff:127.0.0.1",  # IPv4-mapped loopback smuggled in v6
        "::1",  # IPv6 loopback
    ],
)
def test_resolve_and_pin_rejects_non_global(monkeypatch, bad_ip):
    monkeypatch.setattr(
        sources.socket, "getaddrinfo", _make_fake_getaddrinfo({"x": bad_ip})
    )
    with pytest.raises(ValueError):
        sources._resolve_and_pin("x", 443)


def test_resolve_and_pin_deny_by_default_mixed(monkeypatch):
    # Resolver returns [public, private] — must refuse rather than pick public
    # (the private one could be served on a later connect / retry: rebinding).
    monkeypatch.setattr(
        sources.socket,
        "getaddrinfo",
        _make_fake_getaddrinfo({"x": [PUBLIC_GH_IP, "10.0.0.5"]}),
    )
    with pytest.raises(ValueError):
        sources._resolve_and_pin("x", 443)


def test_resolve_and_pin_dns_failure_is_valueerror(monkeypatch):
    def _boom(*a, **k):
        raise socket.gaierror("nope")

    monkeypatch.setattr(sources.socket, "getaddrinfo", _boom)
    with pytest.raises(ValueError):
        sources._resolve_and_pin("x", 443)


# ---------------------------------------------------------------------------
# Pinned connection actually dials the vetted IP (not a re-resolution)
# ---------------------------------------------------------------------------
def test_pinned_https_connection_dials_pinned_ip(monkeypatch):
    captured = {}

    def fake_create_connection(addr, timeout=None, source_address=None):
        captured["addr"] = addr
        return object()

    monkeypatch.setattr(sources.socket, "create_connection", fake_create_connection)

    conn = sources._PinnedHTTPSConnection(
        "api.github.com", PUBLIC_GH_IP, port=443, timeout=30
    )

    class _FakeCtx:
        def wrap_socket(self, sock, server_hostname=None):
            captured["server_hostname"] = server_hostname
            return sock

    conn._context = _FakeCtx()  # avoid a real TLS handshake
    conn.connect()

    # Socket dials the PINNED IP; SNI/cert validation use the real hostname.
    assert captured["addr"] == (PUBLIC_GH_IP, 443)
    assert captured["server_hostname"] == "api.github.com"


# ---------------------------------------------------------------------------
# fetch_url end-to-end: pinning, manual redirect, denial paths
# ---------------------------------------------------------------------------
def test_happy_path_allowlisted_host(monkeypatch):
    calls = []
    monkeypatch.setattr(
        sources.socket,
        "getaddrinfo",
        _make_fake_getaddrinfo({"api.github.com": PUBLIC_GH_IP}),
    )
    monkeypatch.setattr(
        sources,
        "_http_exchange",
        _make_fake_exchange([_FakeResponse(200, body=b'{"ok":true}')], calls),
    )
    out = sources.fetch_url("https://api.github.com/repos/x/commits/main")
    assert out == b'{"ok":true}'
    assert len(calls) == 1
    # Connection was pinned to the resolved, vetted IP.
    assert calls[0]["pinned_ip"] == PUBLIC_GH_IP


def test_rebinding_redirect_denied(monkeypatch):
    # Hop 1 resolves PUBLIC and 302s to an allowlisted host that resolves PRIVATE.
    # The second resolve is classified and denied (rebinding across hops).
    calls = []
    monkeypatch.setattr(
        sources.socket,
        "getaddrinfo",
        _make_fake_getaddrinfo(
            {"api.github.com": PUBLIC_GH_IP, "raw.githubusercontent.com": "10.0.0.5"}
        ),
    )
    monkeypatch.setattr(
        sources,
        "_http_exchange",
        _make_fake_exchange(
            [
                _FakeResponse(
                    302, headers={"Location": "https://raw.githubusercontent.com/evil"}
                ),
                _FakeResponse(200, body=b"SHOULD-NOT-REACH"),
            ],
            calls,
        ),
    )
    assert sources.fetch_url("https://api.github.com/x") is None
    # Only the first hop ran; the private redirect target was never dialed.
    assert len(calls) == 1


def test_redirect_to_internal_host_denied(monkeypatch):
    # Allowlisted hostname that resolves to an internal IP must be refused at the
    # resolve-and-pin layer (not just by IP-literal blocking).
    calls = []
    monkeypatch.setattr(
        sources, "ALLOWED_URL_HOSTS", sources.ALLOWED_URL_HOSTS | {"internal.example"}
    )
    monkeypatch.setattr(
        sources.socket,
        "getaddrinfo",
        _make_fake_getaddrinfo(
            {"api.github.com": PUBLIC_GH_IP, "internal.example": "169.254.169.254"}
        ),
    )
    monkeypatch.setattr(
        sources,
        "_http_exchange",
        _make_fake_exchange(
            [
                _FakeResponse(
                    301, headers={"Location": "https://internal.example/secrets"}
                ),
                _FakeResponse(200, body=b"SHOULD-NOT-REACH"),
            ],
            calls,
        ),
    )
    assert sources.fetch_url("https://api.github.com/x") is None
    assert len(calls) == 1


def test_redirect_to_non_allowlisted_host_denied(monkeypatch):
    calls = []
    monkeypatch.setattr(
        sources.socket,
        "getaddrinfo",
        _make_fake_getaddrinfo({"api.github.com": PUBLIC_GH_IP}),
    )
    monkeypatch.setattr(
        sources,
        "_http_exchange",
        _make_fake_exchange(
            [_FakeResponse(302, headers={"Location": "https://evil.example/x"})],
            calls,
        ),
    )
    assert sources.fetch_url("https://api.github.com/x") is None
    assert len(calls) == 1  # second (evil) hop never dialed


def test_manual_redirect_to_allowlisted_public_followed(monkeypatch):
    # A 302 between two allowlisted, public hosts is followed manually (proving
    # auto-redirect is off but legitimate cross-host redirects still work).
    calls = []
    monkeypatch.setattr(
        sources.socket,
        "getaddrinfo",
        _make_fake_getaddrinfo(
            {
                "api.github.com": PUBLIC_GH_IP,
                "raw.githubusercontent.com": "185.199.108.133",
            }
        ),
    )
    monkeypatch.setattr(
        sources,
        "_http_exchange",
        _make_fake_exchange(
            [
                _FakeResponse(
                    302,
                    headers={"Location": "https://raw.githubusercontent.com/x/data"},
                ),
                _FakeResponse(200, body=b"PAYLOAD"),
            ],
            calls,
        ),
    )
    out = sources.fetch_url("https://api.github.com/x")
    assert out == b"PAYLOAD"
    assert len(calls) == 2
    assert calls[1]["pinned_ip"] == "185.199.108.133"


def test_credentials_dropped_on_cross_host_redirect(monkeypatch):
    calls = []
    monkeypatch.setattr(
        sources.socket,
        "getaddrinfo",
        _make_fake_getaddrinfo(
            {
                "api.github.com": PUBLIC_GH_IP,
                "raw.githubusercontent.com": "185.199.108.133",
            }
        ),
    )
    monkeypatch.setattr(
        sources,
        "_http_exchange",
        _make_fake_exchange(
            [
                _FakeResponse(
                    302,
                    headers={"Location": "https://raw.githubusercontent.com/x/data"},
                ),
                _FakeResponse(200, body=b"PAYLOAD"),
            ],
            calls,
        ),
    )
    out = sources.fetch_url(
        "https://api.github.com/x", headers={"Authorization": "token SECRET"}
    )
    assert out == b"PAYLOAD"
    # First hop carried the credential; the cross-host hop must not.
    assert calls[0]["headers"].get("Authorization") == "token SECRET"
    assert "Authorization" not in calls[1]["headers"]


def test_redirect_loop_capped(monkeypatch):
    # Endless self-redirect (allowlisted, public) terminates at MAX_REDIRECT_HOPS.
    calls = []
    monkeypatch.setattr(
        sources.socket,
        "getaddrinfo",
        _make_fake_getaddrinfo({"api.github.com": PUBLIC_GH_IP}),
    )
    responses = [
        _FakeResponse(302, headers={"Location": "https://api.github.com/loop"})
        for _ in range(sources.MAX_REDIRECT_HOPS + 5)
    ]
    monkeypatch.setattr(sources, "_http_exchange", _make_fake_exchange(responses, calls))
    assert sources.fetch_url("https://api.github.com/x") is None
    assert len(calls) == sources.MAX_REDIRECT_HOPS + 1
