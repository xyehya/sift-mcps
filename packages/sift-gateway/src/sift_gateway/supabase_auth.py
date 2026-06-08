"""Shared Supabase JWT identity resolver for the SIFT gateway (PR03A / Batch A).

This module is the single Gateway-owned authority that turns a Supabase-issued
JWT into a SIFT app principal (operator / agent / service) with status, role,
case memberships, and MCP tool scopes. It is used by:

- REST ``AuthMiddleware`` (``auth.py``)
- the FastMCP ``TokenVerifier`` on ``/mcp`` (``mcp_endpoint.py``)
- the Gateway -> Portal auth callbacks (``server.py`` -> case-dashboard)

Identity is proven by Supabase Auth; *policy* (case/tool/evidence/audit) stays
SIFT-owned (D24/D30).

Secrets discipline (enforced throughout): raw JWTs, refresh tokens, temporary
passwords, the Supabase anon key, and the service-role key are never logged,
``repr``-ed, audited, stored in Postgres, or placed in exceptions. Only the
non-secret 16-hex SHA-256 fingerprint of an access token is ever surfaced.
"""

from __future__ import annotations

import asyncio
import logging
import os
import secrets
import time
from dataclasses import dataclass, field
from typing import Any

import httpx

from sift_gateway.identity import CaseMembership, Identity
from sift_gateway.token_gen import token_digest, token_fingerprint

logger = logging.getLogger(__name__)

# Default positive-result cache TTL (seconds).
_DEFAULT_CACHE_TTL = 30
# Bound on bearer token length (DoS guard, mirrors auth.py).
_MAX_TOKEN_LENGTH = 8192
# Network timeout for Supabase Auth HTTP calls.
_HTTP_TIMEOUT = httpx.Timeout(10.0, read=10.0)


# ---------------------------------------------------------------------------
# Typed denial reasons
# ---------------------------------------------------------------------------


class SupabaseAuthError(Exception):
    """Base error for Supabase auth/identity failures.

    Carries an int ``http_status`` and a str ``reason`` so the portal callback
    boundary can map a denial to an HTTP response without leaking internals.
    Never embed raw token material in the message.
    """

    http_status: int = 401
    reason: str = "auth_error"

    def __init__(self, message: str | None = None, *, reason: str | None = None,
                 http_status: int | None = None) -> None:
        if reason is not None:
            self.reason = reason
        if http_status is not None:
            self.http_status = http_status
        super().__init__(message or self.reason)


class InvalidTokenError(SupabaseAuthError):
    http_status = 401
    reason = "invalid_token"


class TokenExpiredError(SupabaseAuthError):
    http_status = 401
    reason = "token_expired"


class PrincipalNotMappedError(SupabaseAuthError):
    """Valid JWT but no matching active app principal."""

    http_status = 403
    reason = "principal_not_mapped"


class PrincipalDisabledError(SupabaseAuthError):
    http_status = 403
    reason = "principal_disabled"


class AmbiguousPrincipalError(SupabaseAuthError):
    """One auth.users.id maps to more than one app principal — fail closed.

    The partial unique indexes guarantee uniqueness per source table, but the
    union view spans operator/agent/service. A token must resolve to exactly one
    principal; anything else is privilege-confusion and is denied.
    """

    http_status = 403
    reason = "ambiguous_principal"


class PrincipalForbiddenError(SupabaseAuthError):
    """Authenticated but not authorized for the requested surface/action."""

    http_status = 403
    reason = "forbidden"


class PrincipalNotFoundError(SupabaseAuthError):
    """Target principal id did not match any row (e.g. revoke of a bad id)."""

    http_status = 404
    reason = "principal_not_found"


class SupabaseUnavailableError(SupabaseAuthError):
    http_status = 503
    reason = "supabase_unavailable"


class AdminCapabilityError(SupabaseAuthError):
    """A required Supabase Admin capability (e.g. session revoke) is missing."""

    http_status = 500
    reason = "admin_capability_missing"


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class SupabaseAuthConfig:
    """Parsed ``auth.supabase`` + ``auth.legacy`` config plus resolved env secrets.

    Env secrets (``url``/``anon_key``/``service_role_key``) are read from the
    process environment by name only; they are never sourced from repo files and
    never logged.
    """

    enabled: bool = False
    url: str | None = None
    anon_key: str | None = None
    service_role_key: str | None = None
    validation: str = "user_api"
    principal_cache_ttl_seconds: int = _DEFAULT_CACHE_TTL
    # legacy flags
    legacy_token_fallback_enabled: bool = True
    legacy_portal_session_enabled: bool = True
    legacy_anonymous_examiner_enabled: bool = False

    @property
    def configured(self) -> bool:
        """True when Supabase auth is enabled AND the required env is present."""
        return bool(self.enabled and self.url and self.anon_key)

    def __repr__(self) -> str:  # pragma: no cover - defensive, no secrets in repr
        return (
            "SupabaseAuthConfig(enabled=%r, url=%r, anon_key=%s, "
            "service_role_key=%s, validation=%r, ttl=%r, "
            "legacy_token_fallback=%r, legacy_portal_session=%r, "
            "legacy_anonymous_examiner=%r)"
            % (
                self.enabled,
                self.url,
                "<set>" if self.anon_key else None,
                "<set>" if self.service_role_key else None,
                self.validation,
                self.principal_cache_ttl_seconds,
                self.legacy_token_fallback_enabled,
                self.legacy_portal_session_enabled,
                self.legacy_anonymous_examiner_enabled,
            )
        )


def _as_bool(value: Any, default: bool) -> bool:
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() in ("1", "true", "yes", "on")
    return bool(value)


def load_supabase_auth_config(config: dict[str, Any]) -> SupabaseAuthConfig:
    """Parse ``auth.supabase`` / ``auth.legacy`` from gateway config.

    Reads ``SUPABASE_URL`` / ``SUPABASE_ANON_KEY`` / ``SUPABASE_SERVICE_ROLE_KEY``
    (or the configured ``*_env`` names) from the environment only.
    """
    auth_cfg = config.get("auth", {})
    if not isinstance(auth_cfg, dict):
        auth_cfg = {}
    sb = auth_cfg.get("supabase", {})
    if not isinstance(sb, dict):
        sb = {}
    legacy = auth_cfg.get("legacy", {})
    if not isinstance(legacy, dict):
        legacy = {}

    url_env = str(sb.get("url_env") or "SUPABASE_URL")
    anon_env = str(sb.get("anon_key_env") or "SUPABASE_ANON_KEY")
    service_env = str(sb.get("service_role_key_env") or "SUPABASE_SERVICE_ROLE_KEY")

    url = (os.environ.get(url_env) or "").strip().rstrip("/") or None
    anon_key = (os.environ.get(anon_env) or "").strip() or None
    service_role_key = (os.environ.get(service_env) or "").strip() or None

    ttl_raw = sb.get("principal_cache_ttl_seconds", _DEFAULT_CACHE_TTL)
    try:
        ttl = int(ttl_raw)
    except (TypeError, ValueError):
        ttl = _DEFAULT_CACHE_TTL
    if ttl < 0:
        ttl = 0

    return SupabaseAuthConfig(
        enabled=_as_bool(sb.get("enabled"), False),
        url=url,
        anon_key=anon_key,
        service_role_key=service_role_key,
        validation=str(sb.get("validation") or "user_api"),
        principal_cache_ttl_seconds=ttl,
        legacy_token_fallback_enabled=_as_bool(legacy.get("token_fallback_enabled"), True),
        legacy_portal_session_enabled=_as_bool(legacy.get("portal_session_enabled"), True),
        legacy_anonymous_examiner_enabled=_as_bool(
            legacy.get("anonymous_examiner_enabled"), False
        ),
    )


# ---------------------------------------------------------------------------
# Supabase Auth HTTP client
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class SupabaseSession:
    """A Supabase session result. Token material is short-lived in memory only."""

    access_token: str
    refresh_token: str | None
    expires_at: int
    sub: str

    @property
    def fingerprint(self) -> str:
        return token_fingerprint(self.access_token)


class SupabaseAuthClient:
    """Async client for the local Supabase Auth (GoTrue) API, v1.26.05.

    Endpoints used:
      - ``GET  /auth/v1/user``                       (validate access token)
      - ``POST /auth/v1/token?grant_type=password``  (operator/agent login)
      - ``POST /auth/v1/token?grant_type=refresh_token``
      - ``POST /auth/v1/admin/users``                (Admin: create user)
      - ``DELETE /auth/v1/admin/users/{id}``         (Admin: delete user)
      - ``PUT  /auth/v1/admin/users/{id}``           (Admin: update/disable)

    D31 records that pinned Supabase v1.26.05 does not expose per-user admin
    session logout; revocation deletes the auth user instead.
    """

    def __init__(self, config: SupabaseAuthConfig, *, client: httpx.AsyncClient | None = None) -> None:
        if not config.url or not config.anon_key:
            raise SupabaseUnavailableError("Supabase URL/anon key not configured")
        self._config = config
        self._url = config.url
        self._anon_key = config.anon_key
        self._service_role_key = config.service_role_key
        self._own_client = client is None
        self._client = client or httpx.AsyncClient(timeout=_HTTP_TIMEOUT)

    async def aclose(self) -> None:
        if self._own_client:
            await self._client.aclose()

    # -- validation -------------------------------------------------------

    async def get_user(self, access_token: str) -> dict[str, Any]:
        """Validate an access token via ``GET /auth/v1/user``. Returns the user dict.

        Raises ``InvalidTokenError`` / ``TokenExpiredError`` on rejection.
        """
        if not access_token or len(access_token) > _MAX_TOKEN_LENGTH:
            raise InvalidTokenError("missing or oversized token")
        try:
            resp = await self._client.get(
                f"{self._url}/auth/v1/user",
                headers={
                    "Authorization": f"Bearer {access_token}",
                    "apikey": self._anon_key,
                },
            )
        except httpx.HTTPError as exc:
            raise SupabaseUnavailableError("Supabase Auth unreachable") from exc
        if resp.status_code == 200:
            return resp.json()
        if resp.status_code in (401, 403):
            # GoTrue returns 401/403 for expired/invalid tokens.
            raise InvalidTokenError("Supabase rejected token")
        raise SupabaseUnavailableError(f"Supabase /user returned {resp.status_code}")

    # -- grants -----------------------------------------------------------

    async def password_grant(self, email: str, password: str) -> SupabaseSession:
        try:
            resp = await self._client.post(
                f"{self._url}/auth/v1/token",
                params={"grant_type": "password"},
                headers={"apikey": self._anon_key, "Content-Type": "application/json"},
                json={"email": email, "password": password},
            )
        except httpx.HTTPError as exc:
            raise SupabaseUnavailableError("Supabase Auth unreachable") from exc
        if resp.status_code != 200:
            raise InvalidTokenError("invalid credentials")
        return self._session_from_grant(resp.json())

    async def refresh_grant(self, refresh_token: str) -> SupabaseSession:
        try:
            resp = await self._client.post(
                f"{self._url}/auth/v1/token",
                params={"grant_type": "refresh_token"},
                headers={"apikey": self._anon_key, "Content-Type": "application/json"},
                json={"refresh_token": refresh_token},
            )
        except httpx.HTTPError as exc:
            raise SupabaseUnavailableError("Supabase Auth unreachable") from exc
        if resp.status_code != 200:
            raise InvalidTokenError("invalid refresh token")
        return self._session_from_grant(resp.json())

    def _session_from_grant(self, data: dict[str, Any]) -> SupabaseSession:
        access_token = str(data.get("access_token") or "")
        if not access_token:
            raise InvalidTokenError("grant returned no access token")
        user = data.get("user") or {}
        sub = str(user.get("id") or data.get("sub") or "")
        expires_at = data.get("expires_at")
        if expires_at is None:
            expires_in = int(data.get("expires_in") or 3600)
            expires_at = int(time.time()) + expires_in
        return SupabaseSession(
            access_token=access_token,
            refresh_token=data.get("refresh_token"),
            expires_at=int(expires_at),
            sub=sub,
        )

    # -- admin ------------------------------------------------------------

    def _admin_headers(self) -> dict[str, str]:
        if not self._service_role_key:
            raise AdminCapabilityError("service-role key not configured for Admin API")
        return {
            "apikey": self._service_role_key,
            "Authorization": f"Bearer {self._service_role_key}",
            "Content-Type": "application/json",
        }

    async def admin_create_user(
        self, email: str, password: str, *, user_metadata: dict[str, Any] | None = None
    ) -> str:
        """Create a confirmed Supabase Auth user. Returns the new auth.users id."""
        try:
            resp = await self._client.post(
                f"{self._url}/auth/v1/admin/users",
                headers=self._admin_headers(),
                json={
                    "email": email,
                    "password": password,
                    "email_confirm": True,
                    "user_metadata": user_metadata or {},
                },
            )
        except httpx.HTTPError as exc:
            raise SupabaseUnavailableError("Supabase Admin unreachable") from exc
        if resp.status_code not in (200, 201):
            raise SupabaseAuthError(
                "admin user creation failed", reason="admin_create_failed", http_status=502
            )
        data = resp.json()
        user_id = str(data.get("id") or (data.get("user") or {}).get("id") or "")
        if not user_id:
            raise SupabaseAuthError(
                "admin user creation returned no id", reason="admin_create_failed",
                http_status=502,
            )
        return user_id

    async def admin_update_user_password(self, user_id: str, new_password: str) -> None:
        """Update a Supabase Auth user's password (A1-BOOTSTRAP: forced-reset path).

        Called after the operator has authenticated with the temporary installer
        password and wants to set a permanent one. Uses
        ``PUT /auth/v1/admin/users/{id}`` with ``{password: new_password}``.
        The new_password is never logged or stored.
        """
        try:
            resp = await self._client.put(
                f"{self._url}/auth/v1/admin/users/{user_id}",
                headers=self._admin_headers(),
                json={"password": new_password},
            )
        except httpx.HTTPError as exc:
            raise SupabaseUnavailableError("Supabase Admin unreachable") from exc
        if resp.status_code not in (200, 204):
            raise SupabaseAuthError(
                "admin password update failed", reason="admin_update_failed",
                http_status=502,
            )

    async def admin_revoke_user(self, user_id: str, *, delete: bool = True) -> None:
        """Revoke a Supabase user (D31 revocation model).

        The pinned Supabase v1.26.05 GoTrue does NOT expose per-user admin
        session logout (``POST /admin/users/{id}/logout`` returns 404, confirmed
        live on the VM, fork F-13). Revocation therefore deletes the auth user
        via ``DELETE /admin/users/{id}`` (confirmed 200): deleting the user
        invalidates its refresh tokens and blocks future logins. Already-issued
        short-lived access JWTs are denied within the resolver cache TTL because
        the app principal is marked revoked and ``get_user`` fails once the user
        is gone; the caller (``SupabaseAuthCallbacks.revoke_principal``) also
        invalidates the resolver cache proactively. ``delete=False`` performs no
        Supabase-side action and relies on the app-principal disable + cache
        invalidation alone.
        """
        if not delete:
            return
        try:
            deleted = await self._client.delete(
                f"{self._url}/auth/v1/admin/users/{user_id}",
                headers=self._admin_headers(),
            )
        except httpx.HTTPError as exc:
            raise SupabaseUnavailableError("Supabase Admin unreachable") from exc
        # 404 == user already gone → idempotent revoke, treat as success.
        if deleted.status_code not in (200, 204, 404):
            raise SupabaseAuthError(
                "admin user delete failed", reason="admin_delete_failed",
                http_status=502,
            )


# ---------------------------------------------------------------------------
# Principal repository (Postgres, read-only here)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class PrincipalRecord:
    """An app principal resolved from ``auth.users.id``."""

    principal_type: str  # operator | agent | service
    principal_id: str
    auth_user_id: str
    display_name: str | None
    email: str | None
    status: str
    system_role: str | None
    default_case_id: str | None
    case_memberships: tuple[CaseMembership, ...] = ()
    tool_scopes: tuple[str, ...] = ()


class SupabasePrincipalRepository:
    """Read-only Postgres lookups against the FROZEN C1 schema (PR01 + PR03A).

    Writes (agent/service issuance, revoke) are handled separately by the
    issuance helpers in :class:`SupabaseIdentityResolver`; this class only reads.
    """

    def __init__(self, dsn: str) -> None:
        self._dsn = dsn

    def _connect(self):
        try:
            import psycopg
        except ImportError as exc:  # pragma: no cover - deployment env
            raise RuntimeError("psycopg is required for principal lookups") from exc
        return psycopg.connect(self._dsn)

    def lookup_by_auth_user_id(self, auth_user_id: str) -> PrincipalRecord | None:
        """Resolve a Supabase ``auth.users.id`` to exactly one active principal.

        Returns the principal even when disabled (caller fails closed on status)
        so the audit trail can distinguish unmapped from disabled. Raises
        :class:`AmbiguousPrincipalError` (B2) when the auth user is linked to
        more than one app principal — never fail open on ambiguity.
        """
        with self._connect() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    select principal_type, principal_id::text, auth_user_id::text,
                           display_name, email, status, principal_role,
                           default_case_id::text
                    from app.principal_identities
                    where auth_user_id = %s
                    order by principal_type, principal_id
                    """,
                    (auth_user_id,),
                )
                rows = cur.fetchall()
                if not rows:
                    return None
                if len(rows) > 1:
                    # B2: the partial unique indexes only guarantee uniqueness
                    # PER source table; an auth.users.id linked across
                    # operator/agent/service tables would resolve ambiguously.
                    # Fail closed rather than silently picking one principal.
                    raise AmbiguousPrincipalError(
                        "auth user maps to multiple app principals"
                    )
                row = rows[0]
                (
                    principal_type,
                    principal_id,
                    resolved_auth_user_id,
                    display_name,
                    email,
                    status,
                    principal_role,
                    default_case_id,
                ) = row
                memberships = self._load_memberships(cur, principal_type, principal_id)
                scopes = self._load_scopes(cur, principal_type, principal_id)
        return PrincipalRecord(
            principal_type=str(principal_type),
            principal_id=str(principal_id),
            auth_user_id=str(resolved_auth_user_id),
            display_name=display_name,
            email=email,
            status=str(status),
            system_role=str(principal_role) if principal_role else None,
            default_case_id=str(default_case_id) if default_case_id else None,
            case_memberships=memberships,
            tool_scopes=scopes,
        )

    def _load_memberships(
        self, cur: Any, principal_type: str, principal_id: str
    ) -> tuple[CaseMembership, ...]:
        # Only operators have case_members rows in PR01/PR03A.
        if principal_type != "operator":
            return ()
        cur.execute(
            """
            select case_id::text, role
            from app.case_members
            where operator_profile_id = %s and status = 'active'
            order by case_id
            """,
            (principal_id,),
        )
        return tuple(
            CaseMembership(case_id=str(cid), role=str(role)) for cid, role in cur.fetchall()
        )

    def _load_scopes(
        self, cur: Any, principal_type: str, principal_id: str
    ) -> tuple[str, ...]:
        column = {
            "operator": "operator_profile_id",
            "agent": "agent_id",
            "service": "service_identity_id",
        }.get(principal_type)
        if column is None:
            return ()
        # B5/B-11: PR03 has no active-case context in the resolver, so a
        # case-scoped grant (case_id not null) cannot be safely applied to one
        # specific case. Load ONLY global (case_id is null) scopes here; case-
        # scoped rows stay inert until B-11 wires active-case context into tool
        # authorization. Applying case-scoped rows globally would over-grant.
        cur.execute(
            f"""
            select distinct scope
            from app.principal_tool_scopes
            where {column} = %s and status = 'active' and case_id is null
            order by scope
            """,
            (principal_id,),
        )
        return tuple(str(scope) for (scope,) in cur.fetchall() if scope)

    def list_principals(
        self, *, owner_operator_profile_id: str | None = None
    ) -> list[dict[str, Any]]:
        """List agent + service app principals (NO token material).

        When ``owner_operator_profile_id`` is given, only agents owned by that
        operator are returned (and no service principals, which have no owner
        column). When None, all agents and services are returned. Each dict
        carries its active GLOBAL tool scopes only (case_id is null), reusing the
        B5 global-only rule. Never reads ``mcp_tokens`` or any raw token.
        """
        principals: list[dict[str, Any]] = []
        with self._connect() as conn:
            with conn.cursor() as cur:
                if owner_operator_profile_id is not None:
                    cur.execute(
                        """
                        select id::text, display_name, agent_type, status,
                               auth_user_id::text, owner_user_id::text
                        from app.agents
                        where owner_user_id = %s
                        order by display_name, id
                        """,
                        (owner_operator_profile_id,),
                    )
                else:
                    cur.execute(
                        """
                        select id::text, display_name, agent_type, status,
                               auth_user_id::text, owner_user_id::text
                        from app.agents
                        order by display_name, id
                        """
                    )
                for row in cur.fetchall():
                    pid, display_name, agent_type, status, auth_user_id, owner_id = row
                    principals.append({
                        "principal_type": "agent",
                        "principal_id": str(pid),
                        "display_name": display_name,
                        "status": str(status),
                        "type": str(agent_type) if agent_type else None,
                        "auth_user_id": str(auth_user_id) if auth_user_id else None,
                        "owner_user_id": str(owner_id) if owner_id else None,
                        "tool_scopes": list(self._load_scopes(cur, "agent", str(pid))),
                    })

                # Service identities have no owner column; only owner/admin (i.e.
                # the all-principals path) sees them.
                if owner_operator_profile_id is None:
                    cur.execute(
                        """
                        select id::text, name, service_type, status,
                               auth_user_id::text
                        from app.service_identities
                        order by name, id
                        """
                    )
                    for row in cur.fetchall():
                        pid, name, service_type, status, auth_user_id = row
                        principals.append({
                            "principal_type": "service",
                            "principal_id": str(pid),
                            "display_name": name,
                            "status": str(status),
                            "type": str(service_type) if service_type else None,
                            "auth_user_id": str(auth_user_id) if auth_user_id else None,
                            "owner_user_id": None,
                            "tool_scopes": list(
                                self._load_scopes(cur, "service", str(pid))
                            ),
                        })
        return principals


# ---------------------------------------------------------------------------
# Identity resolver
# ---------------------------------------------------------------------------


@dataclass
class _CacheEntry:
    identity: Identity
    expires_at: float


class SupabaseIdentityResolver:
    """Validate a Supabase JWT and resolve it to a SIFT :class:`Identity`.

    Fail-closed on invalid/expired tokens and on unmapped/disabled principals.
    Positive results may be cached for ``principal_cache_ttl_seconds`` keyed by
    the non-secret token fingerprint (never the raw token). Negatives are not
    cached.
    """

    def __init__(
        self,
        config: SupabaseAuthConfig,
        *,
        client: SupabaseAuthClient | None = None,
        repository: SupabasePrincipalRepository | None = None,
    ) -> None:
        self._config = config
        self._client = client
        self._repository = repository
        self._cache: dict[str, _CacheEntry] = {}
        self._cache_lock = asyncio.Lock()

    @property
    def config(self) -> SupabaseAuthConfig:
        return self._config

    async def resolve(self, access_token: str, *, source_ip: str | None = None,
                      auth_surface: str = "rest") -> Identity:
        """Resolve a Supabase access token to an Identity or raise SupabaseAuthError."""
        if not access_token or len(access_token) > _MAX_TOKEN_LENGTH:
            raise InvalidTokenError("missing or oversized token")
        if self._client is None or self._repository is None:
            raise SupabaseUnavailableError("Supabase resolver not configured")

        # B8: key the cache on the FULL 64-hex sha256 digest, not the 16-hex
        # audit fingerprint, so a fingerprint collision cannot serve another
        # principal's Identity. The digest is one-way; the raw token is never
        # stored.
        cache_key = token_digest(access_token)
        cached = await self._cache_get(cache_key)
        if cached is not None:
            # Re-stamp surface/source_ip so cached identity reflects this request.
            return _restamp(cached, source_ip=source_ip, auth_surface=auth_surface)

        user = await self._client.get_user(access_token)
        auth_user_id = str(user.get("id") or "")
        if not auth_user_id:
            raise InvalidTokenError("token has no subject")

        record = await asyncio.to_thread(
            self._repository.lookup_by_auth_user_id, auth_user_id
        )
        if record is None:
            raise PrincipalNotMappedError("no app principal for auth user")
        if record.status != "active":
            raise PrincipalDisabledError(f"principal status={record.status}")

        identity = _record_to_identity(
            record,
            access_token=access_token,
            source_ip=source_ip,
            auth_surface=auth_surface,
        )
        await self._cache_put(cache_key, identity)
        return identity

    async def try_resolve(self, access_token: str, *, source_ip: str | None = None,
                          auth_surface: str = "rest") -> Identity | None:
        """Like :meth:`resolve` but returns None instead of raising on denial."""
        try:
            return await self.resolve(
                access_token, source_ip=source_ip, auth_surface=auth_surface
            )
        except SupabaseAuthError:
            return None

    # -- cache ------------------------------------------------------------

    async def _cache_get(self, cache_key: str) -> Identity | None:
        ttl = self._config.principal_cache_ttl_seconds
        if ttl <= 0:
            return None
        async with self._cache_lock:
            entry = self._cache.get(cache_key)
            if entry is None:
                return None
            if entry.expires_at <= time.monotonic():
                self._cache.pop(cache_key, None)
                return None
            return entry.identity

    async def _cache_put(self, cache_key: str, identity: Identity) -> None:
        ttl = self._config.principal_cache_ttl_seconds
        if ttl <= 0:
            return
        async with self._cache_lock:
            self._cache[cache_key] = _CacheEntry(
                identity=identity, expires_at=time.monotonic() + ttl
            )

    def invalidate(self, access_token: str) -> None:
        """Drop a cached identity (best-effort, used on logout/revoke)."""
        self._cache.pop(token_digest(access_token), None)

    def invalidate_principal(self, auth_user_id: str) -> None:
        """Drop every cached identity for an auth user (D31 revoke).

        The cache is keyed by token digest, so a revoke cannot target a single
        key; scan and drop all entries whose resolved identity belongs to this
        auth user, closing the residual access-token window proactively (in
        addition to the app-principal disable + ``get_user`` failing once the
        user is deleted). Best-effort and synchronous, like :meth:`invalidate`.
        """
        if not auth_user_id:
            return
        stale = [
            k for k, e in self._cache.items()
            if e.identity.auth_user_id == auth_user_id
        ]
        for k in stale:
            self._cache.pop(k, None)


def _record_to_identity(
    record: PrincipalRecord,
    *,
    access_token: str,
    source_ip: str | None,
    auth_surface: str,
) -> Identity:
    role = _system_role_to_role(record.principal_type, record.system_role)
    # default_case_id provides the active case hint when present.
    case_id = record.default_case_id
    return Identity(
        principal=record.display_name or record.principal_id,
        principal_type=record.principal_type
        if record.principal_type in ("agent", "service")
        else "user",
        token_id=record.principal_id,
        agent_id=record.principal_id if record.principal_type == "agent" else None,
        created_by=None,
        role=role,
        source_ip=source_ip,
        auth_surface=auth_surface,
        case_id=case_id,
        tool_scopes=frozenset(record.tool_scopes),
        token_fingerprint=token_fingerprint(access_token),
        auth_user_id=record.auth_user_id,
        principal_id=record.principal_id,
        system_role=record.system_role,
        case_memberships=tuple(record.case_memberships),
    )


def _system_role_to_role(principal_type: str, system_role: str | None) -> str:
    """Map an app principal to the coarse legacy ``role`` used by middleware.

    Operators map to readonly/examiner by system_role; agents/services keep
    their existing coarse roles for downstream policy compatibility.
    """
    if principal_type == "agent":
        return "agent"
    if principal_type == "service":
        return "service"
    if system_role == "readonly":
        return "readonly"
    return "examiner"


def _restamp(identity: Identity, *, source_ip: str | None, auth_surface: str) -> Identity:
    if identity.source_ip == source_ip and identity.auth_surface == auth_surface:
        return identity
    from dataclasses import replace

    return replace(identity, source_ip=source_ip, auth_surface=auth_surface)


# ---------------------------------------------------------------------------
# Gateway -> Portal auth callbacks (FROZEN CONTRACT C3)
# ---------------------------------------------------------------------------


def _principal_dict(record: PrincipalRecord) -> dict[str, Any]:
    """Serialize a principal for the portal boundary. No token material."""
    return {
        "principal_type": record.principal_type,
        "principal_id": record.principal_id,
        "auth_user_id": record.auth_user_id,
        "display_name": record.display_name,
        "email": record.email,
        "system_role": record.system_role,
        "status": record.status,
        "case_memberships": [
            {"case_id": m.case_id, "role": m.role} for m in record.case_memberships
        ],
    }


class SupabaseAuthCallbacks:
    """Decoupled auth callbacks handed to ``create_dashboard_v2_app(supabase_auth=...)``.

    case-dashboard must NOT import sift_gateway. These methods accept primitives
    and return plain dicts (or None / raise an error with int .http_status and
    str .reason). All privileged auth decisions are audited here. No raw token
    material is ever stored, logged, or audited.
    """

    def __init__(
        self,
        config: SupabaseAuthConfig,
        client: SupabaseAuthClient,
        repository: SupabasePrincipalRepository,
        resolver: SupabaseIdentityResolver,
        *,
        audit: Any | None = None,
        agent_issuance: "AgentServiceIssuance | None" = None,
    ) -> None:
        self._config = config
        self._client = client
        self._repository = repository
        self._resolver = resolver
        self._audit = audit
        self._issuance = agent_issuance

    # -- audit helper -----------------------------------------------------

    def _audit_log(self, *, tool: str, summary: str, extra: dict[str, Any]) -> None:
        if self._audit is None:
            return
        try:
            self._audit.log(
                tool=tool,
                params={},
                result_summary=summary,
                source="gateway_portal_auth",
                extra=extra,
            )
        except Exception as exc:  # pragma: no cover - audit must never break auth
            logger.warning("portal auth audit write failed: %s", exc)

    # -- login ------------------------------------------------------------

    async def login(self, email: str, password: str, source_ip: str | None) -> dict[str, Any]:
        session = await self._client.password_grant(email, password)
        record = await asyncio.to_thread(
            self._repository.lookup_by_auth_user_id, session.sub
        )
        if record is None:
            self._audit_log(
                tool="portal_login",
                summary="rejected: principal_not_mapped",
                extra={"source_ip": source_ip, "auth_user_id": session.sub,
                       "fingerprint": session.fingerprint, "reason": "principal_not_mapped"},
            )
            raise PrincipalNotMappedError("no app principal for user")
        if record.status != "active":
            self._audit_log(
                tool="portal_login",
                summary=f"rejected: principal_{record.status}",
                extra={"source_ip": source_ip, "auth_user_id": session.sub,
                       "principal_id": record.principal_id, "principal_type": record.principal_type,
                       "fingerprint": session.fingerprint, "reason": "principal_disabled"},
            )
            raise PrincipalDisabledError(f"principal status={record.status}")
        if record.principal_type != "operator":
            # Only operators may log into the portal.
            self._audit_log(
                tool="portal_login",
                summary="rejected: non_operator_portal_login",
                extra={"source_ip": source_ip, "principal_id": record.principal_id,
                       "principal_type": record.principal_type,
                       "fingerprint": session.fingerprint, "reason": "forbidden"},
            )
            raise PrincipalForbiddenError("only operators may log into the portal")

        self._audit_log(
            tool="portal_login",
            summary="accepted",
            extra={"source_ip": source_ip, "auth_user_id": session.sub,
                   "principal_id": record.principal_id, "principal_type": "operator",
                   "system_role": record.system_role, "fingerprint": session.fingerprint},
        )
        return {
            "access_token": session.access_token,
            "refresh_token": session.refresh_token,
            "expires_at": session.expires_at,
            "sub": session.sub,
            "fingerprint": session.fingerprint,
            "principal": _principal_dict(record),
        }

    # -- resolve ----------------------------------------------------------

    async def resolve(self, access_token: str, source_ip: str | None) -> dict[str, Any] | None:
        try:
            user = await self._client.get_user(access_token)
            auth_user_id = str(user.get("id") or "")
            if not auth_user_id:
                return None
            record = await asyncio.to_thread(
                self._repository.lookup_by_auth_user_id, auth_user_id
            )
        except SupabaseAuthError:
            # Includes AmbiguousPrincipalError (B2): fail closed to None.
            return None
        if record is None or record.status != "active":
            return None
        return _principal_dict(record)

    # -- refresh ----------------------------------------------------------

    async def refresh(self, refresh_token: str, source_ip: str | None) -> dict[str, Any] | None:
        try:
            session = await self._client.refresh_grant(refresh_token)
            record = await asyncio.to_thread(
                self._repository.lookup_by_auth_user_id, session.sub
            )
        except SupabaseAuthError:
            # Includes AmbiguousPrincipalError (B2): fail closed to None.
            return None
        if record is None or record.status != "active" or record.principal_type != "operator":
            return None
        self._audit_log(
            tool="portal_refresh",
            summary="accepted",
            extra={"source_ip": source_ip, "principal_id": record.principal_id,
                   "principal_type": "operator", "fingerprint": session.fingerprint},
        )
        return {
            "access_token": session.access_token,
            "refresh_token": session.refresh_token,
            "expires_at": session.expires_at,
            "sub": session.sub,
            "fingerprint": session.fingerprint,
            "principal": _principal_dict(record),
        }

    # -- logout -----------------------------------------------------------

    async def logout(self, access_token: str | None, source_ip: str | None) -> None:
        fingerprint = token_fingerprint(access_token) if access_token else None
        if access_token:
            self._resolver.invalidate(access_token)
        self._audit_log(
            tool="portal_logout",
            summary="logout",
            extra={"source_ip": source_ip, "fingerprint": fingerprint},
        )

    # -- list -------------------------------------------------------------

    async def list_principals(
        self, creator: dict[str, Any], source_ip: str | None
    ) -> list[dict[str, Any]]:
        """List agent/service principals for the operator roster (doc 19 §7.1).

        owner/admin operators see ALL agent + service principals; a non-owner
        operator sees only agents they own. Returns dicts with NO token material
        (no access/refresh tokens, no temp passwords, no raw PR02 token).
        """
        creator = creator or {}
        if creator.get("principal_type") not in (None, "operator"):
            # Only operators may view the roster.
            raise PrincipalForbiddenError("only operators may list principals")

        system_role = creator.get("system_role")
        if system_role in ("owner", "admin"):
            owner_filter = None  # all principals
        else:
            owner_filter = creator.get("principal_id")
            if not owner_filter:
                raise PrincipalForbiddenError("operator cannot list principals")

        principals = await asyncio.to_thread(
            self._repository.list_principals,
            owner_operator_profile_id=owner_filter,
        )
        self._audit_log(
            tool="principals_listed",
            summary=f"listed {len(principals)} principal(s)",
            extra={"source_ip": source_ip,
                   "principal_id": creator.get("principal_id"),
                   "principal_type": "operator",
                   "system_role": system_role,
                   "scope": "all" if owner_filter is None else "owned",
                   "count": len(principals)},
        )
        return principals

    # -- forced reset (A1-BOOTSTRAP) --------------------------------------

    async def forced_reset(
        self,
        access_token: str,
        new_password: str,
        source_ip: str | None,
    ) -> None:
        """Complete a forced password reset for an operator on first login.

        Validates the current access token, verifies the principal is an operator
        in 'invited' status, updates the Supabase password via Admin API, and
        marks the operator principal as 'active'. Never logs passwords.

        Raises SupabaseAuthError on denial; AdminCapabilityError when the
        service-role key is not configured (can't call Admin API).
        """
        if not self._client._service_role_key:
            raise AdminCapabilityError("service-role key required for forced reset")
        if not new_password or len(new_password) < 8:
            raise SupabaseAuthError(
                "new_password too short (minimum 8 characters)",
                reason="password_too_short",
                http_status=400,
            )

        # Re-validate the current token to get the auth_user_id.
        user = await self._client.get_user(access_token)
        auth_user_id = str(user.get("id") or "")
        if not auth_user_id:
            raise InvalidTokenError("token has no subject")

        record = await asyncio.to_thread(
            self._repository.lookup_by_auth_user_id, auth_user_id
        )
        if record is None:
            raise PrincipalNotMappedError("no app principal for user")
        if record.principal_type != "operator":
            raise PrincipalForbiddenError("forced reset only applies to operators")
        if record.status != "invited":
            raise SupabaseAuthError(
                "forced reset only allowed for invited (first-login) operators",
                reason="not_forced_reset",
                http_status=409,
            )

        # Update password via Admin API (new_password never stored or logged).
        await self._client.admin_update_user_password(auth_user_id, new_password)

        # Mark operator principal as active in Postgres.
        await asyncio.to_thread(
            self._activate_operator_principal, record.principal_id
        )

        self._audit_log(
            tool="portal_forced_reset",
            summary="forced reset accepted",
            extra={
                "source_ip": source_ip,
                "auth_user_id": auth_user_id,
                "principal_id": record.principal_id,
                "principal_type": "operator",
            },
        )

        # Proactively drop cached identities so the old token is not served
        # after the principal transitions from invited → active.
        self._resolver.invalidate_principal(auth_user_id)

    def _activate_operator_principal(self, principal_id: str) -> None:
        """Transition operator status from 'invited' to 'active' in Postgres."""
        if self._repository is None:
            return
        try:
            with self._repository._connect() as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        update app.operator_profiles
                        set status = 'active', updated_at = now()
                        where id = %s and status = 'invited'
                        """,
                        (principal_id,),
                    )
                conn.commit()
        except Exception as exc:
            logger.warning("forced_reset: operator activate failed: %s", exc)
            raise

    # -- issuance / revoke (delegated) ------------------------------------

    async def issue_principal(
        self,
        creator: dict[str, Any],
        kind: str,
        display_name: str,
        system_role: str | None,
        tool_scopes: list[str],
        case_id: str | None,
        source_ip: str | None,
    ) -> dict[str, Any]:
        if self._issuance is None:
            raise AdminCapabilityError("agent/service issuance not configured")
        return await self._issuance.issue_principal(
            creator, kind, display_name, system_role, tool_scopes, case_id, source_ip
        )

    async def revoke_principal(
        self,
        creator: dict[str, Any],
        principal_type: str,
        principal_id: str,
        source_ip: str | None,
    ) -> None:
        if self._issuance is None:
            raise AdminCapabilityError("agent/service issuance not configured")
        auth_user_id = await self._issuance.revoke_principal(
            creator, principal_type, principal_id, source_ip
        )
        # D31: proactively drop the revoked principal's cached identities so the
        # residual access-token window is closed even before the cache TTL.
        if auth_user_id:
            self._resolver.invalidate_principal(auth_user_id)


# ---------------------------------------------------------------------------
# Agent / service JWT issuance (write path)
# ---------------------------------------------------------------------------


def _require_admin_creator(creator: dict[str, Any]) -> None:
    if (creator or {}).get("system_role") not in ("owner", "admin"):
        raise PrincipalForbiddenError("creator must be owner/admin")


class AgentServiceIssuance:
    """Create/revoke agent & service principals as Supabase users + app rows.

    Writes the app.agents / app.service_identities row, links auth_user_id, and
    obtains a one-time session for the new principal. The temporary password is
    generated in memory and never persisted/logged.
    """

    def __init__(
        self,
        config: SupabaseAuthConfig,
        client: SupabaseAuthClient,
        *,
        dsn: str,
        audit: Any | None = None,
    ) -> None:
        self._config = config
        self._client = client
        self._dsn = dsn
        self._audit = audit

    def _connect(self):
        import psycopg

        return psycopg.connect(self._dsn)

    def _audit_log(self, *, tool: str, summary: str, extra: dict[str, Any]) -> None:
        if self._audit is None:
            return
        try:
            self._audit.log(tool=tool, params={}, result_summary=summary,
                            source="gateway_principal_issuance", extra=extra)
        except Exception as exc:  # pragma: no cover
            logger.warning("issuance audit write failed: %s", exc)

    async def issue_principal(
        self,
        creator: dict[str, Any],
        kind: str,
        display_name: str,
        system_role: str | None,
        tool_scopes: list[str],
        case_id: str | None,
        source_ip: str | None,
    ) -> dict[str, Any]:
        _require_admin_creator(creator)
        if kind not in ("agent", "service"):
            raise PrincipalForbiddenError("kind must be agent or service")

        # High-entropy temporary password, in memory only.
        temp_password = secrets.token_urlsafe(32)
        # Synthetic email scoped to the deployment; never a human inbox.
        local = secrets.token_hex(8)
        email = f"{kind}+{local}@principals.sift.local"

        auth_user_id = await self._client.admin_create_user(
            email, temp_password, user_metadata={"sift_principal_kind": kind,
                                                  "display_name": display_name}
        )
        try:
            principal_id = await asyncio.to_thread(
                self._insert_principal_row, kind, display_name, auth_user_id,
                system_role, tool_scopes, case_id, creator,
            )
        except Exception:
            # Roll back the orphaned Supabase user on app-row failure.
            try:
                await self._client.admin_revoke_user(auth_user_id, delete=True)
            except SupabaseAuthError:
                pass
            raise

        session = await self._client.password_grant(email, temp_password)
        # temp_password goes out of scope here; never stored.

        self._audit_log(
            tool="principal_created",
            summary=f"{kind} created",
            extra={"source_ip": source_ip, "principal_type": kind,
                   "principal_id": principal_id, "auth_user_id": auth_user_id,
                   "created_by": creator.get("principal_id"),
                   "fingerprint": session.fingerprint},
        )
        return {
            "principal_type": kind,
            "principal_id": principal_id,
            "auth_user_id": auth_user_id,
            "access_token": session.access_token,
            "refresh_token": session.refresh_token,
            "expires_at": session.expires_at,
            "fingerprint": session.fingerprint,
            "display_name": display_name,
        }

    def _insert_principal_row(
        self,
        kind: str,
        display_name: str,
        auth_user_id: str,
        system_role: str | None,
        tool_scopes: list[str],
        case_id: str | None,
        creator: dict[str, Any],
    ) -> str:
        principal_type_col = (
            "agent_type" if kind == "agent" else "service_type"
        )
        # default principal_role
        ptype = system_role or ("ai" if kind == "agent" else "worker")
        with self._connect() as conn:
            with conn.cursor() as cur:
                if kind == "agent":
                    cur.execute(
                        """
                        insert into app.agents
                          (display_name, agent_type, status, owner_user_id,
                           default_case_id, auth_user_id)
                        values (%s, %s, 'active', %s, %s, %s)
                        returning id::text
                        """,
                        (display_name, ptype, creator.get("principal_id"),
                         case_id, auth_user_id),
                    )
                    principal_id = cur.fetchone()[0]
                    scope_col = "agent_id"
                else:
                    cur.execute(
                        """
                        insert into app.service_identities
                          (name, service_type, status, auth_user_id)
                        values (%s, %s, 'active', %s)
                        returning id::text
                        """,
                        (display_name, ptype, auth_user_id),
                    )
                    principal_id = cur.fetchone()[0]
                    scope_col = "service_identity_id"
                for scope in tool_scopes or []:
                    cur.execute(
                        f"""
                        insert into app.principal_tool_scopes
                          ({scope_col}, case_id, scope, status)
                        values (%s, %s, %s, 'active')
                        """,
                        (principal_id, case_id, scope),
                    )
            conn.commit()
        return str(principal_id)

    async def revoke_principal(
        self,
        creator: dict[str, Any],
        principal_type: str,
        principal_id: str,
        source_ip: str | None,
    ) -> str | None:
        _require_admin_creator(creator)
        # B4: distinguish "no such principal" (zero-row update) from "row
        # disabled". A bad/typo'd principal_id must NOT silently commit and audit
        # a false success.
        matched, auth_user_id = await asyncio.to_thread(
            self._disable_principal_row, principal_type, principal_id
        )
        if not matched:
            raise PrincipalNotFoundError(
                f"no {principal_type} principal with that id"
            )
        if auth_user_id:
            # D31: delete the Supabase auth user (pinned v1.26.05 lacks admin
            # session logout); kills refresh tokens + future logins, idempotent.
            await self._client.admin_revoke_user(auth_user_id, delete=True)
        self._audit_log(
            tool="principal_revoked",
            summary=f"{principal_type} revoked",
            extra={"source_ip": source_ip, "principal_type": principal_type,
                   "principal_id": principal_id, "auth_user_id": auth_user_id,
                   "revoked_by": creator.get("principal_id")},
        )
        # Returned so the callback can invalidate the resolver cache (D31).
        return auth_user_id

    def _disable_principal_row(
        self, principal_type: str, principal_id: str
    ) -> tuple[bool, str | None]:
        """Return (matched, auth_user_id). matched is False on a zero-row update."""
        table = {"agent": "app.agents", "service": "app.service_identities"}.get(
            principal_type
        )
        if table is None:
            raise PrincipalForbiddenError("principal_type must be agent or service")
        with self._connect() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    f"""
                    update {table}
                    set status = 'revoked', updated_at = now()
                    where id = %s
                    returning auth_user_id::text
                    """,
                    (principal_id,),
                )
                row = cur.fetchone()
                if row is None:
                    # No matching principal — abort without committing changes.
                    conn.rollback()
                    return (False, None)
                auth_user_id = row[0]
                scope_col = "agent_id" if principal_type == "agent" else "service_identity_id"
                cur.execute(
                    f"""
                    update app.principal_tool_scopes
                    set status = 'revoked', updated_at = now()
                    where {scope_col} = %s and status = 'active'
                    """,
                    (principal_id,),
                )
            conn.commit()
        return (True, auth_user_id if auth_user_id else None)


# ---------------------------------------------------------------------------
# Tool authorization (B-10) — single helper for list + call
# ---------------------------------------------------------------------------


def is_tool_allowed(identity: Identity | None, tool_name: str) -> bool:
    """Return True if ``identity`` may list/call ``tool_name`` (B-10).

    Grammar (DB-backed ``tool_scopes``, already normalized to active rows):
      - ``mcp:*``            -> all tools
      - ``tool:<name>``      -> exactly that normalized tool name
      - ``namespace:<pfx>``  -> tools whose name begins ``<pfx>_``
    Unknown scope strings grant nothing. A principal with no active target scope
    may not list/call ordinary tools. The SAME function is used by
    ``on_list_tools`` (filter advertised tools) and ``on_call_tool`` (reject
    before dispatch), guaranteeing list/call consistency.
    """
    if identity is None:
        return False
    scopes = identity.tool_scopes or frozenset()
    if not scopes:
        return False
    for scope in scopes:
        if scope == "mcp:*":
            return True
        if scope.startswith("tool:"):
            if tool_name == scope[len("tool:"):]:
                return True
        elif scope.startswith("namespace:"):
            prefix = scope[len("namespace:"):]
            if prefix and tool_name.startswith(f"{prefix}_"):
                return True
        # any other scope string grants nothing
    return False


def is_scope_satisfied(identity: Identity | None, required_scope: str) -> bool:
    """Return True if ``identity`` holds the manifest-declared ``required_scope``.

    BATCH-D2 / H1 add-on scope enforcement. A tool's ``required_scopes`` are
    additional, manifest-declared grants the caller must hold to invoke that
    add-on tool — distinct from the gateway tool-scope authorization in
    :func:`is_tool_allowed`. The check is fail-closed: an identity with no
    scopes (or none matching) is denied.

    Matching rules against the caller's normalized ``tool_scopes``:
      - ``mcp:*`` held by the caller satisfies any required scope (superuser).
      - An exact scope-string match satisfies the requirement.
      - A required ``tool:<name>``/``namespace:<pfx>`` is satisfied by a caller
        scope that grants that tool/namespace via :func:`is_tool_allowed`.
    """
    if identity is None:
        return False
    scopes = identity.tool_scopes or frozenset()
    if not scopes:
        return False
    if "mcp:*" in scopes:
        return True
    if required_scope in scopes:
        return True
    # Allow grammar-aware coverage when the requirement is itself expressed in
    # the tool:/namespace: grammar (e.g. a tool requiring tool:foo is satisfied
    # by a caller holding namespace:foo_pfx). Plain capability scopes (e.g.
    # "cti:read") only match by exact membership above.
    if required_scope.startswith("tool:"):
        return is_tool_allowed(identity, required_scope[len("tool:"):])
    return False


def legacy_default_scopes() -> frozenset[str]:
    """The compatibility default for legacy PR02 tokens (mcp:* equivalent)."""
    return frozenset({"mcp:*"})
