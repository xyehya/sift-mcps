"""Postgres-backed hash-only MCP/service token registry.

PR02 keeps this intentionally small: DB lookup by peppered token hash, scoped
metadata for identity resolution, and narrow lifecycle writes for portal token
management. Legacy ``gateway.yaml`` tokens remain a fallback outside this
module.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Protocol
from uuid import uuid4

logger = logging.getLogger(__name__)

from sift_gateway.token_gen import token_fingerprint, token_hash


CONTROL_PLANE_DSN_ENV = "SIFT_CONTROL_PLANE_DSN"
TOKEN_PEPPER_ENV = "SIFT_TOKEN_PEPPER"


@dataclass(frozen=True)
class RegistryToken:
    id: str
    token_fingerprint: str
    role: str
    principal: str
    principal_type: str
    agent_id: str | None
    service_identity_id: str | None
    created_by: str | None
    case_id: str | None
    label: str | None
    expires_at: datetime
    scopes: frozenset[str] = field(default_factory=frozenset)


class TokenRegistry(Protocol):
    def lookup_token(self, token: str) -> RegistryToken | None: ...

    def list_tokens(self) -> list[dict[str, Any]]: ...

    def create_token(
        self,
        *,
        raw_token: str,
        agent_id: str,
        label: str,
        role: str,
        created_by: str,
        expires_at: str | None,
        case_id: str | None = None,
    ) -> RegistryToken: ...

    def revoke_token(self, token_id: str, *, revoked_by: str) -> str | None: ...

    def rotate_token(
        self,
        token_id: str,
        *,
        new_raw_token: str,
        rotated_by: str,
    ) -> RegistryToken | None: ...

    def reactivate_token(self, token_id: str) -> bool: ...


def registry_config(config: dict[str, Any]) -> tuple[str | None, str | None]:
    token_cfg = config.get("token_registry", {})
    if not isinstance(token_cfg, dict):
        token_cfg = {}
    control_cfg = config.get("control_plane", {})
    if not isinstance(control_cfg, dict):
        control_cfg = {}
    dsn_env = str(control_cfg.get("postgres_dsn_env") or CONTROL_PLANE_DSN_ENV)
    pepper_env = str(token_cfg.get("pepper_env") or TOKEN_PEPPER_ENV)
    dsn = (
        token_cfg.get("postgres_dsn")
        or control_cfg.get("postgres_dsn")
        or os.environ.get(dsn_env)
        or os.environ.get(CONTROL_PLANE_DSN_ENV)
    )
    pepper = (
        token_cfg.get("pepper")
        or os.environ.get(pepper_env)
        or os.environ.get(TOKEN_PEPPER_ENV)
    )
    return str(dsn).strip() if dsn else None, str(pepper) if pepper else None


def create_token_registry(config: dict[str, Any]) -> TokenRegistry | None:
    dsn, pepper = registry_config(config)
    if not dsn:
        return None
    if not pepper:
        return None
    return PostgresTokenRegistry(dsn=dsn, pepper=pepper)


class PostgresTokenRegistry:
    def __init__(self, *, dsn: str, pepper: str) -> None:
        self._dsn = dsn
        self._pepper = pepper

    def _connect(self):
        try:
            import psycopg
        except ImportError as exc:  # pragma: no cover - depends on deployment env
            raise RuntimeError("psycopg is required for token registry access") from exc
        return psycopg.connect(self._dsn)

    def lookup_token(self, token: str) -> RegistryToken | None:
        digest = token_hash(token, self._pepper)
        with self._connect() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    select
                      t.id::text,
                      t.token_fingerprint,
                      t.status,
                      t.agent_id::text,
                      t.service_identity_id::text,
                      t.created_by_user_id::text,
                      t.case_id::text,
                      t.label,
                      t.expires_at,
                      t.revoked_at,
                      coalesce(t.metadata, '{}'::jsonb)::text,
                      coalesce(array_agg(s.scope order by s.scope)
                        filter (where s.scope is not null), array[]::text[]) as scopes
                    from app.mcp_tokens t
                    left join app.mcp_token_scopes s on s.token_id = t.id
                    where t.token_hash = %s
                    group by t.id
                    """,
                    (digest,),
                )
                row = cur.fetchone()
                if row is None:
                    return None
                record = self._row_to_registry_token(row)
                if record is not None:
                    cur.execute(
                        "update app.mcp_tokens set last_used_at = now() where id = %s",
                        (record.id,),
                    )
                    conn.commit()
                return record

    def _row_to_registry_token(self, row: tuple[Any, ...]) -> RegistryToken | None:
        (
            token_id,
            fingerprint,
            status,
            agent_uuid,
            service_uuid,
            created_by,
            case_id,
            label,
            expires_at,
            revoked_at,
            metadata_raw,
            scopes,
        ) = row
        if status != "active" or revoked_at is not None:
            return None
        if _to_aware_utc(expires_at) <= datetime.now(timezone.utc):
            return None
        scope_set = frozenset(str(scope) for scope in (scopes or []) if str(scope))
        if not scope_set:
            return None

        import json

        try:
            metadata = json.loads(metadata_raw) if isinstance(metadata_raw, str) else {}
        except ValueError as exc:
            logger.warning("Corrupt token metadata (token_id %s): %s", token_id, exc)
            metadata = {}
        role = str(metadata.get("role") or ("service" if service_uuid else "agent"))
        legacy_agent_id = metadata.get("legacy_agent_id")
        if service_uuid:
            principal_type = "service"
            principal = str(metadata.get("name") or service_uuid)
        elif agent_uuid or legacy_agent_id:
            principal_type = "agent"
            principal = str(legacy_agent_id or agent_uuid)
        else:
            principal_type = "service" if role == "service" else "agent"
            principal = str(metadata.get("principal") or label or token_id)
        return RegistryToken(
            id=str(token_id),
            token_fingerprint=str(fingerprint),
            role=role,
            principal=principal,
            principal_type=principal_type,
            agent_id=str(legacy_agent_id or agent_uuid) if (legacy_agent_id or agent_uuid) else None,
            service_identity_id=str(service_uuid) if service_uuid else None,
            created_by=str(created_by) if created_by else metadata.get("created_by"),
            case_id=str(case_id) if case_id else None,
            label=str(label) if label else None,
            expires_at=_to_aware_utc(expires_at),
            scopes=scope_set,
        )

    def list_tokens(self) -> list[dict[str, Any]]:
        with self._connect() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    select id::text, token_fingerprint, label, status, created_at,
                           expires_at, revoked_at, last_used_at, case_id::text,
                           coalesce(metadata, '{}'::jsonb)::text
                    from app.mcp_tokens
                    order by created_at
                    """
                )
                rows = cur.fetchall()
        return [_public_token_row(row) for row in rows]

    def create_token(
        self,
        *,
        raw_token: str,
        agent_id: str,
        label: str,
        role: str,
        created_by: str,
        expires_at: str | None,
        case_id: str | None = None,
    ) -> RegistryToken:
        token_id = str(uuid4())
        expires_dt = _parse_expiry(expires_at, role)
        fingerprint = token_fingerprint(raw_token)
        digest = token_hash(raw_token, self._pepper)
        bound_case_id = str(case_id).strip() if case_id else None
        metadata = {
            "role": role,
            "legacy_agent_id": agent_id,
            "created_by": created_by,
        }
        if bound_case_id:
            metadata["default_case_id"] = bound_case_id
        scopes = ["mcp:*"] if role == "agent" else ["portal:read"]
        with self._connect() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    select 1
                    from app.mcp_tokens
                    where revoked_at is null
                      and status = 'active'
                      and metadata->>'legacy_agent_id' = %s
                    limit 1
                    """,
                    (agent_id,),
                )
                if cur.fetchone() is not None:
                    raise ValueError(f"Active token already exists for agent_id '{agent_id}'")
                cur.execute(
                    """
                    insert into app.mcp_tokens
                      (id, token_hash, token_fingerprint, status, label, expires_at,
                       case_id, metadata)
                    values (%s, %s, %s, 'active', %s, %s, %s, %s::jsonb)
                    """,
                    (
                        token_id,
                        digest,
                        fingerprint,
                        label,
                        expires_dt,
                        bound_case_id,
                        _json(metadata),
                    ),
                )
                for scope in scopes:
                    cur.execute(
                        """
                        insert into app.mcp_token_scopes (token_id, scope)
                        values (%s, %s)
                        """,
                        (token_id, scope),
                    )
            conn.commit()
        return RegistryToken(
            id=token_id,
            token_fingerprint=fingerprint,
            role=role,
            principal=agent_id,
            principal_type="agent",
            agent_id=agent_id,
            service_identity_id=None,
            created_by=created_by,
            case_id=bound_case_id,
            label=label,
            expires_at=expires_dt,
            scopes=frozenset(scopes),
        )

    def revoke_token(self, token_id: str, *, revoked_by: str) -> str | None:
        revoked_at = datetime.now(timezone.utc)
        with self._connect() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    update app.mcp_tokens
                    set status = 'revoked',
                        revoked_at = %s,
                        metadata = coalesce(metadata, '{}'::jsonb)
                          || jsonb_build_object('revoked_by', %s),
                        updated_at = now()
                    where id = %s and revoked_at is null and status != 'revoked'
                    returning revoked_at
                    """,
                    (revoked_at, revoked_by, token_id),
                )
                row = cur.fetchone()
            conn.commit()
        if row is None:
            return None
        return _iso(_to_aware_utc(row[0]))

    def rotate_token(
        self,
        token_id: str,
        *,
        new_raw_token: str,
        rotated_by: str,
    ) -> RegistryToken | None:
        with self._connect() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    select label, expires_at, case_id::text,
                           coalesce(metadata, '{}'::jsonb)::text, revoked_at, status
                    from app.mcp_tokens
                    where id = %s
                    """,
                    (token_id,),
                )
                old = cur.fetchone()
                if old is None or old[4] is not None or old[5] == "revoked":
                    return None
                label, expires_at, case_id, metadata_raw, _revoked_at, _status = old
                import json

                metadata = json.loads(metadata_raw)
                agent_id = str(metadata.get("legacy_agent_id") or "unknown")
                role = str(metadata.get("role") or "agent")
                new_id = str(uuid4())
                fingerprint = token_fingerprint(new_raw_token)
                digest = token_hash(new_raw_token, self._pepper)
                new_metadata = dict(metadata)
                new_metadata["created_by"] = rotated_by
                cur.execute(
                    """
                    update app.mcp_tokens
                    set status = 'revoked',
                        revoked_at = now(),
                        metadata = coalesce(metadata, '{}'::jsonb)
                          || jsonb_build_object('rotated_by', %s),
                        updated_at = now()
                    where id = %s
                    """,
                    (rotated_by, token_id),
                )
                cur.execute(
                    """
                    insert into app.mcp_tokens
                      (id, token_hash, token_fingerprint, status, label, expires_at,
                       case_id, metadata)
                    values (%s, %s, %s, 'active', %s, %s, %s, %s::jsonb)
                    """,
                    (
                        new_id,
                        digest,
                        fingerprint,
                        str(label or ""),
                        _to_aware_utc(expires_at),
                        str(case_id) if case_id else None,
                        _json(new_metadata),
                    ),
                )
                scopes = ["mcp:*"] if role == "agent" else ["portal:read"]
                for scope in scopes:
                    cur.execute(
                        """
                        insert into app.mcp_token_scopes (token_id, scope)
                        values (%s, %s)
                        """,
                        (new_id, scope),
                    )
            conn.commit()
        return RegistryToken(
            id=new_id,
            token_fingerprint=fingerprint,
            role=role,
            principal=agent_id,
            principal_type="agent",
            agent_id=agent_id,
            service_identity_id=None,
            created_by=rotated_by,
            case_id=str(case_id) if case_id else None,
            label=str(label or ""),
            expires_at=_to_aware_utc(expires_at),
            scopes=frozenset(scopes),
        )

    def reactivate_token(self, token_id: str) -> bool:
        with self._connect() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    update app.mcp_tokens
                    set status = 'active', revoked_at = null, updated_at = now()
                    where id = %s and revoked_at is not null
                    """,
                    (token_id,),
                )
                changed = cur.rowcount > 0
            conn.commit()
        return changed


def _to_aware_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _parse_expiry(expires_at: str | None, role: str) -> datetime:
    if expires_at:
        return _to_aware_utc(datetime.fromisoformat(str(expires_at).replace("Z", "+00:00")))
    from datetime import timedelta

    days = 90 if role == "agent" else 30
    return datetime.now(timezone.utc) + timedelta(days=days)


def _iso(value: datetime) -> str:
    return _to_aware_utc(value).isoformat()


def _json(value: dict[str, Any]) -> str:
    import json

    return json.dumps(value, separators=(",", ":"))


def _public_token_row(row: tuple[Any, ...]) -> dict[str, Any]:
    import json

    (
        token_id,
        fingerprint,
        label,
        status,
        created_at,
        expires_at,
        revoked_at,
        last_used_at,
        case_id,
        metadata_raw,
    ) = row
    try:
        metadata = json.loads(metadata_raw) if isinstance(metadata_raw, str) else {}
    except ValueError as exc:
        logger.warning("Corrupt token metadata in public row (token_id %s): %s", token_id, exc)
        metadata = {}
    return {
        "token_id": str(token_id),
        "token_fingerprint": str(fingerprint),
        "agent_id": metadata.get("legacy_agent_id"),
        "label": label or "",
        "role": metadata.get("role", "agent"),
        "created_by": metadata.get("created_by"),
        "created_at": _iso(_to_aware_utc(created_at)),
        "expires_at": _iso(_to_aware_utc(expires_at)),
        "revoked_at": _iso(_to_aware_utc(revoked_at)) if revoked_at else None,
        "last_used_at": _iso(_to_aware_utc(last_used_at)) if last_used_at else None,
        "case_id": str(case_id) if case_id else metadata.get("default_case_id"),
        "status": status,
    }
