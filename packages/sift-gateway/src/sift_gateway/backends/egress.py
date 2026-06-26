"""Shared runtime egress policy for the gateway's own outbound HTTP connections.

SEC-3 — a single anti-SSRF / anti-DNS-rebinding control for **every** HTTP MCP
backend connection the gateway makes itself: manifest fetch, the runtime tool
proxy, and the ``HttpMCPBackend`` health/list/call session. The gateway is a
policy boundary; this guards its OWN egress (the add-on subprocess has no DB
creds and is out of scope here).

One implementation classifies the resolved destination and — crucially — returns
the **pinned** IP(s). Callers connect to a vetted address instead of a freshly
re-resolved one, which closes the TOCTOU / DNS-rebinding window: a name that
resolves public at validation time cannot be swung to a private/loopback address
between the check and the connect, because the connect targets the pinned IP, not
the hostname.

TLS hostname verification is preserved end-to-end. We dial the pinned IP but keep
the original hostname as the TLS ``server_hostname`` (SNI) via the httpcore
``sni_hostname`` request extension, so the certificate is still verified against
the hostname — we never connect to ``https://<ip>`` naked. Redirects are not
followed (``follow_redirects=False``); a 30x to an internal address is therefore
never chased.

Fail-closed by default. Private/loopback/link-local/multicast/reserved/
unspecified/unique-local addresses are rejected for IPv4 and IPv6 (including
IPv4-mapped IPv6, ``0.0.0.0`` and ``::``). An operator may explicitly permit
specific internal destinations via ``SIFT_EGRESS_ALLOWED_HOSTS`` /
``SIFT_EGRESS_ALLOWED_CIDRS`` (or a per-call allow, used by the wintools join
where the DSS-CAN-019 bound host authorizes egress to that one LAN host).
"""

from __future__ import annotations

import ipaddress
import logging
import os
import socket
from dataclasses import dataclass
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

# Default ports keep the validated destination, the pinned connection, and the
# emitted Host header internally consistent.
_DEFAULT_PORTS = {"http": 80, "https": 443}


@dataclass(frozen=True)
class EgressTarget:
    """A vetted outbound destination with its pinned resolved address(es).

    ``pinned_ips`` are literal IP strings that passed the egress policy at
    validation time; the actual TCP connect targets one of these (never a
    re-resolution of ``hostname``), which is the anti-rebinding control.
    ``hostname`` remains the TLS SNI / certificate-verification identity.
    """

    hostname: str
    port: int
    scheme: str
    pinned_ips: tuple[str, ...]

    @property
    def host_header(self) -> str:
        """``Host`` header value (hostname, with port only when non-default)."""
        host = self.hostname
        # Bracket IPv6 literals for the Host header.
        try:
            if isinstance(ipaddress.ip_address(host), ipaddress.IPv6Address):
                host = f"[{host}]"
        except ValueError:
            pass
        if self.port == _DEFAULT_PORTS.get(self.scheme):
            return host
        return f"{host}:{self.port}"


def _ip_is_blocked(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """True when ``ip`` is a non-routable / internal address the gateway must not dial.

    Covers IPv4 and IPv6. IPv4-mapped IPv6 (``::ffff:a.b.c.d``) is unwrapped and
    classified as its embedded IPv4 so an attacker cannot smuggle a private v4
    target inside a v6 literal. ``0.0.0.0`` / ``::`` are caught by
    ``is_unspecified``; IPv6 ULA (``fc00::/7``) and deprecated site-local
    (``fec0::/10``) by ``is_private`` / ``is_site_local``.
    """
    mapped = getattr(ip, "ipv4_mapped", None)
    if mapped is not None:
        ip = mapped
    if (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    ):
        return True
    # is_site_local exists only on IPv6Address (deprecated fec0::/10).
    if getattr(ip, "is_site_local", False):
        return True
    return False


def _parse_allowlist_env() -> tuple[frozenset[str], tuple[ipaddress._BaseNetwork, ...]]:
    """Operator-configured internal-egress allowlist (default empty = fail-closed).

    ``SIFT_EGRESS_ALLOWED_HOSTS`` — os.pathsep- or comma-separated hostnames that
    may resolve to an otherwise-blocked address (matched case-insensitively).
    ``SIFT_EGRESS_ALLOWED_CIDRS`` — os.pathsep- or comma-separated CIDRs whose
    addresses are permitted even when classified internal.
    """
    hosts: set[str] = set()
    raw_hosts = os.environ.get("SIFT_EGRESS_ALLOWED_HOSTS", "")
    for part in raw_hosts.replace(os.pathsep, ",").split(","):
        part = part.strip().lower()
        if part:
            hosts.add(part)

    cidrs: list[ipaddress._BaseNetwork] = []
    raw_cidrs = os.environ.get("SIFT_EGRESS_ALLOWED_CIDRS", "")
    for part in raw_cidrs.replace(os.pathsep, ",").split(","):
        part = part.strip()
        if not part:
            continue
        try:
            cidrs.append(ipaddress.ip_network(part, strict=False))
        except ValueError:
            logger.warning("Ignoring invalid SIFT_EGRESS_ALLOWED_CIDRS entry: %r", part)
    return frozenset(hosts), tuple(cidrs)


def validate_egress_url(
    url: str,
    *,
    label: str,
    extra_allowed_hosts: frozenset[str] | set[str] | tuple[str, ...] = (),
    extra_allowed_cidrs: tuple[ipaddress._BaseNetwork, ...] = (),
) -> EgressTarget:
    """Validate ``url`` against the egress policy and return its pinned target.

    Resolves the hostname and rejects the URL if ANY returned address is a
    non-routable/internal address (a rebinder can return both a public and a
    private record, so a single bad answer fails the whole host). Returns the
    de-duplicated set of vetted IPs to pin the connection to.

    ``extra_allowed_hosts`` / ``extra_allowed_cidrs`` augment the operator env
    allowlist for one call (the wintools join passes its DSS-CAN-019 bound host).
    """
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise ValueError(f"{label} must be an http(s) URL with a hostname")
    # Reject embedded credentials (userinfo "@") — they both leak secrets and
    # can disguise the real host in some parsers.
    if parsed.username or parsed.password:
        raise ValueError(f"{label} must not embed credentials in the URL")
    host = parsed.hostname
    if not host:
        raise ValueError(f"{label} must be an http(s) URL with a hostname")

    port = parsed.port or _DEFAULT_PORTS[parsed.scheme]

    allow_hosts, allow_cidrs = _parse_allowlist_env()
    allow_hosts = allow_hosts | {h.strip().lower() for h in extra_allowed_hosts if h}
    allow_cidrs = allow_cidrs + tuple(extra_allowed_cidrs)
    host_allowed = host.lower() in allow_hosts

    def _permitted(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
        if not _ip_is_blocked(ip):
            return True
        if host_allowed:
            return True
        probe = getattr(ip, "ipv4_mapped", None) or ip
        return any(probe in cidr for cidr in allow_cidrs)

    # Literal-IP URL: classify directly, no DNS.
    try:
        literal = ipaddress.ip_address(host)
    except ValueError:
        literal = None
    if literal is not None:
        if not _permitted(literal):
            raise ValueError(f"{label} resolves to a blocked private/link-local address")
        return EgressTarget(host, port, parsed.scheme, (str(literal),))

    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise ValueError(f"{label} hostname could not be resolved") from exc
    if not infos:
        raise ValueError(f"{label} hostname could not be resolved")

    pinned: list[str] = []
    seen: set[str] = set()
    for info in infos:
        ip = ipaddress.ip_address(info[4][0])
        if not _permitted(ip):
            raise ValueError(f"{label} resolves to a blocked private/link-local address")
        text = str(ip)
        if text not in seen:
            seen.add(text)
            pinned.append(text)
    return EgressTarget(host, port, parsed.scheme, tuple(pinned))


def make_pinned_egress_factory(target: EgressTarget, *, tls_cert: str | None = None):
    """Return an ``httpx_client_factory`` that connects only to ``target``'s pinned IP.

    Compatible with the MCP ``streamablehttp_client`` factory contract and the
    FastMCP proxy factory (extra kwargs / ``follow_redirects`` are accepted and
    ignored — redirects are always disabled). The returned client dials the
    pinned IP while verifying TLS against the original hostname.
    """
    import httpx
    from mcp.shared._httpx_utils import (
        MCP_DEFAULT_SSE_READ_TIMEOUT,
        MCP_DEFAULT_TIMEOUT,
    )

    verify: bool | str = tls_cert if tls_cert else True

    def factory(headers=None, timeout=None, auth=None, **_kwargs):
        if timeout is None:
            timeout = httpx.Timeout(MCP_DEFAULT_TIMEOUT, read=MCP_DEFAULT_SSE_READ_TIMEOUT)
        kwargs = {
            "timeout": timeout,
            "follow_redirects": False,
            "transport": _PinnedEgressTransport(target, verify=verify),
        }
        if headers is not None:
            kwargs["headers"] = headers
        if auth is not None:
            kwargs["auth"] = auth
        return httpx.AsyncClient(**kwargs)

    return factory


def _make_pinned_egress_transport(target: EgressTarget, *, verify: bool | str = True):
    """Public-ish constructor used by tests; see :class:`_PinnedEgressTransport`."""
    return _PinnedEgressTransport(target, verify=verify)


# httpx is imported lazily inside functions elsewhere to keep import cost down,
# but the transport subclass needs the base class at definition time.
import httpx  # noqa: E402


class _PinnedEgressTransport(httpx.AsyncBaseTransport):
    """httpx transport that dials a pre-validated pinned IP, not a re-resolved name.

    Each request is rewritten so the connection origin is the pinned IP while the
    ``Host`` header and TLS ``sni_hostname`` stay the original hostname — so the
    server certificate is verified against the hostname (not the IP) yet the
    socket can never reach a rebind target. A request whose host is not the
    validated hostname is refused, so a same-client redirect/rewrite cannot
    escape the pin.
    """

    def __init__(self, target: EgressTarget, *, verify: bool | str = True):
        self._target = target
        if not target.pinned_ips:
            raise ValueError("egress target has no pinned IP")
        self._pinned_ip = target.pinned_ips[0]
        self._inner = httpx.AsyncHTTPTransport(verify=verify, retries=0)

    async def handle_async_request(self, request):
        if request.url.host != self._target.hostname:
            raise httpx.RequestError(
                f"egress pin rejects host {request.url.host!r}; "
                f"only {self._target.hostname!r} is permitted",
                request=request,
            )
        # Dial the pinned IP; preserve hostname for Host header + TLS SNI.
        request.url = request.url.copy_with(host=self._pinned_ip)
        request.headers["Host"] = self._target.host_header
        request.extensions = {**request.extensions, "sni_hostname": self._target.hostname}
        return await self._inner.handle_async_request(request)

    async def aclose(self) -> None:
        await self._inner.aclose()


class _PinnedEgressTransportSync(httpx.BaseTransport):
    """Synchronous twin of :class:`_PinnedEgressTransport` for the manifest fetch."""

    def __init__(self, target: EgressTarget, *, verify: bool | str = True):
        self._target = target
        if not target.pinned_ips:
            raise ValueError("egress target has no pinned IP")
        self._pinned_ip = target.pinned_ips[0]
        self._inner = httpx.HTTPTransport(verify=verify, retries=0)

    def handle_request(self, request):
        if request.url.host != self._target.hostname:
            raise httpx.RequestError(
                f"egress pin rejects host {request.url.host!r}; "
                f"only {self._target.hostname!r} is permitted",
                request=request,
            )
        request.url = request.url.copy_with(host=self._pinned_ip)
        request.headers["Host"] = self._target.host_header
        request.extensions = {**request.extensions, "sni_hostname": self._target.hostname}
        return self._inner.handle_request(request)

    def close(self) -> None:
        self._inner.close()


def build_pinned_sync_client(target: EgressTarget, *, verify: bool | str = True):
    """Return a synchronous ``httpx.Client`` pinned to ``target`` (redirects off).

    Used by the manifest fetch so a manifest URL that resolved public at check
    time cannot rebind to an internal address before the GET.
    """
    return httpx.Client(
        transport=_PinnedEgressTransportSync(target, verify=verify),
        follow_redirects=False,
    )


__all__ = [
    "EgressTarget",
    "validate_egress_url",
    "make_pinned_egress_factory",
    "build_pinned_sync_client",
]
