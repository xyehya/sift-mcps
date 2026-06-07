"""Supabase/Postgres active-case authority for PR03B."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from sift_gateway.identity import Identity


_CASE_KEY_RE = re.compile(r"^[a-z][a-z0-9_-]{2,63}$")
_WRITE_ROLES = frozenset({"operator", "lead", "owner", "admin"})
_SYSTEM_BYPASS_ROLES = frozenset({"owner", "admin"})


class ActiveCaseError(Exception):
    def __init__(self, reason: str, *, http_status: int = 400) -> None:
        super().__init__(reason)
        self.reason = reason
        self.http_status = http_status


@dataclass(frozen=True)
class ActiveCase:
    case_id: str
    case_key: str
    title: str
    description: str | None
    status: str
    artifact_path: str | None
    metadata: dict[str, Any]
    membership_role: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "id": self.case_key,
            "uuid": self.case_id,
            "case_id": self.case_id,
            "case_key": self.case_key,
            "title": self.title,
            "name": self.title,
            "description": self.description,
            "status": self.status,
            "artifact_path": self.artifact_path,
            "case_dir": self.artifact_path,
            "metadata": self.metadata,
            "membership_role": self.membership_role,
        }


def _connect(dsn: str):
    try:
        import psycopg
    except ImportError as exc:  # pragma: no cover - deployment env
        raise RuntimeError("psycopg is required for active-case DB authority") from exc
    return psycopg.connect(dsn)


def _jsonb(value: dict[str, Any]):
    try:
        from psycopg.types.json import Jsonb
    except ImportError:  # pragma: no cover
        return value
    return Jsonb(value)


def _principal_type(principal: Any) -> str | None:
    if isinstance(principal, Identity):
        return "operator" if principal.principal_type == "user" else principal.principal_type
    if isinstance(principal, dict):
        return principal.get("principal_type")
    return None


def _principal_id(principal: Any) -> str | None:
    if isinstance(principal, Identity):
        return principal.principal_id
    if isinstance(principal, dict):
        value = principal.get("principal_id")
        return str(value) if value else None
    return None


def _system_role(principal: Any) -> str | None:
    if isinstance(principal, Identity):
        return principal.system_role
    if isinstance(principal, dict):
        value = principal.get("system_role")
        return str(value) if value else None
    return None


def _default_case_id(principal: Any) -> str | None:
    if isinstance(principal, Identity):
        return principal.case_id
    if isinstance(principal, dict):
        value = principal.get("case_id") or principal.get("default_case_id")
        return str(value) if value else None
    return None


def _membership_role_from_identity(principal: Any, case_id: str) -> str | None:
    memberships = ()
    if isinstance(principal, Identity):
        memberships = principal.case_memberships
        for membership in memberships:
            if membership.case_id == case_id:
                return membership.role
    elif isinstance(principal, dict):
        memberships = principal.get("case_memberships") or ()
        for membership in memberships:
            if isinstance(membership, dict) and str(membership.get("case_id")) == case_id:
                role = membership.get("role")
                return str(role) if role else None
    return None


def _actor_columns(principal: Any) -> tuple[str, str | None]:
    ptype = _principal_type(principal)
    pid = _principal_id(principal)
    if ptype == "operator":
        return "user", pid
    if ptype == "agent":
        return "agent", pid
    if ptype == "service":
        return "service", pid
    return "system", None


class ActiveCaseService:
    """Gateway-owned active-case repository/service.

    The service is intentionally the only DB active-case authority used by the
    Gateway and portal. Legacy env/config/pointer helpers may still exist for
    CLI compatibility, but request paths must use this service.
    """

    def __init__(self, dsn: str, *, audit: Any | None = None) -> None:
        self._dsn = dsn
        self._audit = audit

    def _connect(self):
        return _connect(self._dsn)

    def get_active_case(self, principal: Any | None = None) -> ActiveCase:
        with self._connect() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    select c.id::text, c.case_key, c.title, c.description, c.status,
                           c.legacy_case_dir, c.metadata
                    from app.active_case_state s
                    join app.cases c on c.id = s.active_case_id
                    where s.scope = 'deployment' and s.active_case_id is not null
                    """
                )
                row = cur.fetchone()
                if not row:
                    raise ActiveCaseError("no_active_case", http_status=404)
                case = self._case_from_row(row)
                role = self.membership_role(principal, case.case_id, conn=conn)
                return ActiveCase(**{**case.__dict__, "membership_role": role})

    def get_case_metadata(self, case_id: str, principal: Any) -> ActiveCase:
        with self._connect() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    select id::text, case_key, title, description, status,
                           legacy_case_dir, metadata
                    from app.cases
                    where id = %s or case_key = %s
                    """,
                    (case_id, case_id),
                )
                row = cur.fetchone()
                if not row:
                    raise ActiveCaseError("case_not_found", http_status=404)
                case = self._case_from_row(row)
                role = self.membership_role(principal, case.case_id, conn=conn)
                if role is None:
                    raise ActiveCaseError("case_membership_required", http_status=403)
                return ActiveCase(**{**case.__dict__, "membership_role": role})

    def list_cases(self, principal: Any) -> list[dict[str, Any]]:
        ptype = _principal_type(principal)
        pid = _principal_id(principal)
        sys_role = _system_role(principal)
        with self._connect() as conn:
            with conn.cursor() as cur:
                if ptype == "operator" and sys_role in _SYSTEM_BYPASS_ROLES:
                    cur.execute(
                        """
                        select c.id::text, c.case_key, c.title, c.description, c.status,
                               c.legacy_case_dir, c.metadata, null::text as member_role
                        from app.cases c
                        order by c.created_at desc, c.case_key
                        """
                    )
                elif ptype == "operator" and pid:
                    cur.execute(
                        """
                        select c.id::text, c.case_key, c.title, c.description, c.status,
                               c.legacy_case_dir, c.metadata, cm.role as member_role
                        from app.cases c
                        join app.case_members cm on cm.case_id = c.id
                        where cm.operator_profile_id = %s and cm.status = 'active'
                        order by c.created_at desc, c.case_key
                        """,
                        (pid,),
                    )
                else:
                    default_case = _default_case_id(principal)
                    if not default_case:
                        return []
                    cur.execute(
                        """
                        select c.id::text, c.case_key, c.title, c.description, c.status,
                               c.legacy_case_dir, c.metadata, null::text as member_role
                        from app.cases c
                        where c.id = %s
                        order by c.created_at desc, c.case_key
                        """,
                        (default_case,),
                    )
                return [
                    {
                        **self._case_from_row(row[:7]).as_dict(),
                        "membership_role": row[7],
                    }
                    for row in cur.fetchall()
                ]

    def create_case(self, payload: dict[str, Any], actor: Any) -> ActiveCase:
        ptype = _principal_type(actor)
        pid = _principal_id(actor)
        if ptype != "operator" or not pid:
            raise ActiveCaseError("operator_principal_required", http_status=403)
        if _system_role(actor) not in _SYSTEM_BYPASS_ROLES:
            # Non-admin operators may create cases; they become owner below.
            pass

        case_key = str(payload.get("case_key") or payload.get("case_id") or "").strip()
        if not case_key:
            case_key = self._case_key_from_name(str(payload.get("casename") or "case"))
        if not _CASE_KEY_RE.fullmatch(case_key):
            raise ActiveCaseError("invalid_case_key", http_status=400)
        title = str(payload.get("title") or case_key).strip()
        if not title:
            raise ActiveCaseError("title_required", http_status=400)
        description = payload.get("description")
        if description is not None:
            description = str(description).strip() or None
        artifact_path = payload.get("artifact_path") or payload.get("case_dir")
        artifact_path = str(artifact_path).strip() if artifact_path else None

        metadata = payload.get("metadata") if isinstance(payload.get("metadata"), dict) else {}
        with self._connect() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    insert into app.cases
                      (case_key, legacy_case_id, title, description, status,
                       created_by_user_id, opened_at, legacy_case_dir,
                       legacy_case_yaml_path, metadata, compat_export_status)
                    values
                      (%s, %s, %s, %s, 'active', %s, now(), %s, %s, %s, 'stale')
                    returning id::text, case_key, title, description, status,
                              legacy_case_dir, metadata
                    """,
                    (
                        case_key,
                        case_key,
                        title,
                        description,
                        pid,
                        artifact_path,
                        str(Path(artifact_path) / "CASE.yaml") if artifact_path else None,
                        _jsonb(metadata),
                    ),
                )
                row = cur.fetchone()
                if not row:
                    raise ActiveCaseError("case_create_failed", http_status=500)
                case = self._case_from_row(row)
                cur.execute(
                    """
                    insert into app.case_members
                      (case_id, operator_profile_id, role, status, added_by_user_id)
                    values (%s, %s, 'owner', 'active', %s)
                    on conflict do nothing
                    """,
                    (case.case_id, pid, pid),
                )
                self._insert_audit(
                    cur,
                    event_type="case.created",
                    actor=actor,
                    case_id=case.case_id,
                    status="success",
                    summary=f"created case {case.case_key}",
                    details={"case_key": case.case_key},
                )
                if bool(payload.get("activate", True)):
                    self._set_active_case_cur(cur, case.case_id, actor)
                conn.commit()
        self._notify_audit("case.created", actor, case)
        return ActiveCase(**{**case.__dict__, "membership_role": "owner"})

    def set_active_case(self, case_id: str, actor: Any) -> ActiveCase:
        with self._connect() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    select id::text, case_key, title, description, status,
                           legacy_case_dir, metadata
                    from app.cases
                    where id = %s or case_key = %s
                    """,
                    (case_id, case_id),
                )
                row = cur.fetchone()
                if not row:
                    raise ActiveCaseError("case_not_found", http_status=404)
                case = self._case_from_row(row)
                role = self.membership_role(actor, case.case_id, conn=conn)
                if role not in _WRITE_ROLES:
                    raise ActiveCaseError("active_case_membership_required", http_status=403)
                self._set_active_case_cur(cur, case.case_id, actor)
                conn.commit()
        self._notify_audit("active_case.changed", actor, case)
        return ActiveCase(**{**case.__dict__, "membership_role": role})

    def update_case_metadata(
        self, case_id: str, actor: Any, patch: dict[str, Any]
    ) -> ActiveCase:
        current = self.get_case_metadata(case_id, actor)
        if current.membership_role not in _WRITE_ROLES:
            raise ActiveCaseError("case_metadata_write_forbidden", http_status=403)
        updates: dict[str, Any] = {}
        metadata = dict(current.metadata or {})
        if "title" in patch or "name" in patch:
            updates["title"] = str(patch.get("title") or patch.get("name") or "").strip()
        if "description" in patch:
            value = patch.get("description")
            updates["description"] = str(value).strip() if value is not None else None
        if "status" in patch:
            status = str(patch.get("status") or "").strip()
            if status not in {"draft", "active", "paused", "closed", "archived"}:
                raise ActiveCaseError("invalid_case_status", http_status=400)
            updates["status"] = status
        if "field" in patch:
            field = str(patch.get("field") or "").strip()
            if not field:
                raise ActiveCaseError("field_required", http_status=400)
            if field in {"case_id", "case_key", "id", "legacy_case_dir"}:
                raise ActiveCaseError("protected_field", http_status=400)
            value = patch.get("value", "")
            if field in {"title", "name", "description", "status"}:
                return self.update_case_metadata(case_id, actor, {field: value})
            metadata[field] = value
        if "metadata" in patch:
            if not isinstance(patch["metadata"], dict):
                raise ActiveCaseError("metadata_must_be_object", http_status=400)
            metadata.update(patch["metadata"])
        if not updates and metadata == (current.metadata or {}):
            return current
        with self._connect() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    update app.cases
                    set title = coalesce(%s, title),
                        description = coalesce(%s, description),
                        status = coalesce(%s, status),
                        metadata = %s,
                        updated_at = now()
                    where id = %s
                    returning id::text, case_key, title, description, status,
                              legacy_case_dir, metadata
                    """,
                    (
                        updates.get("title"),
                        updates.get("description"),
                        updates.get("status"),
                        _jsonb(metadata),
                        current.case_id,
                    ),
                )
                row = cur.fetchone()
                if not row:
                    raise ActiveCaseError("case_not_found", http_status=404)
                case = self._case_from_row(row)
                self._insert_audit(
                    cur,
                    event_type="case.metadata.updated",
                    actor=actor,
                    case_id=case.case_id,
                    status="success",
                    summary=f"updated case metadata {case.case_key}",
                    details={"changed": sorted(patch.keys())},
                )
                conn.commit()
        self._notify_audit("case.metadata.updated", actor, case)
        return ActiveCase(**{**case.__dict__, "membership_role": current.membership_role})

    def membership_role(
        self, principal: Any | None, case_id: str, *, conn: Any | None = None
    ) -> str | None:
        if principal is None:
            return None
        sys_role = _system_role(principal)
        if _principal_type(principal) == "operator" and sys_role in _SYSTEM_BYPASS_ROLES:
            return sys_role
        role = _membership_role_from_identity(principal, case_id)
        if role:
            return role
        default_case = _default_case_id(principal)
        if default_case == case_id:
            return _principal_type(principal) or "principal"
        ptype = _principal_type(principal)
        pid = _principal_id(principal)
        if ptype != "operator" or not pid:
            return None
        owns_conn = conn is None
        if owns_conn:
            conn = self._connect()
        try:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    select role
                    from app.case_members
                    where case_id = %s and operator_profile_id = %s
                      and status = 'active'
                    order by created_at desc
                    limit 1
                    """,
                    (case_id, pid),
                )
                row = cur.fetchone()
                return str(row[0]) if row else None
        finally:
            if owns_conn:
                conn.close()

    def require_active_case_for_principal(self, principal: Any | None) -> ActiveCase:
        case = self.get_active_case(principal)
        if self.membership_role(principal, case.case_id) is None:
            raise ActiveCaseError("active_case_membership_required", http_status=403)
        return case

    def _set_active_case_cur(self, cur: Any, case_id: str, actor: Any) -> None:
        ptype, pid = _actor_columns(actor)
        del ptype
        cur.execute(
            """
            insert into app.active_case_state
              (scope, active_case_id, set_by_user_id, set_at,
               compat_export_status, metadata, updated_at)
            values ('deployment', %s, %s, now(), 'stale',
                    jsonb_build_object('authority', 'postgres'), now())
            on conflict (scope) do update
              set active_case_id = excluded.active_case_id,
                  set_by_user_id = excluded.set_by_user_id,
                  set_at = excluded.set_at,
                  compat_export_status = 'stale',
                  metadata = excluded.metadata,
                  updated_at = now()
            """,
            (case_id, pid),
        )
        self._insert_audit(
            cur,
            event_type="active_case.changed",
            actor=actor,
            case_id=case_id,
            status="success",
            summary="deployment active case changed",
            details={"authority": "postgres"},
        )

    def _insert_audit(
        self,
        cur: Any,
        *,
        event_type: str,
        actor: Any,
        case_id: str | None,
        status: str,
        summary: str,
        details: dict[str, Any],
    ) -> None:
        actor_type, actor_id = _actor_columns(actor)
        columns = {
            "user": "actor_user_id",
            "agent": "actor_agent_id",
            "service": "actor_service_identity_id",
        }
        actor_column = columns.get(actor_type)
        fields = ["case_id", "event_type", "actor_type", "source", "status", "summary", "details"]
        values: list[Any] = [case_id, event_type, actor_type, "gateway_active_case", status, summary, _jsonb(details)]
        if actor_column and actor_id:
            fields.insert(3, actor_column)
            values.insert(3, actor_id)
        cur.execute(
            f"""
            insert into app.audit_events ({", ".join(fields)})
            values ({", ".join(["%s"] * len(values))})
            """,
            values,
        )

    def _notify_audit(self, event_type: str, actor: Any, case: ActiveCase) -> None:
        if self._audit is None:
            return
        try:
            principal = getattr(actor, "principal", None)
            if principal is None and isinstance(actor, dict):
                principal = actor.get("display_name") or actor.get("email")
            self._audit.log(
                tool=event_type,
                params={"case_id": case.case_id, "case_key": case.case_key},
                result_summary="success",
                source="gateway_active_case",
                extra={"case_id": case.case_id, "case_key": case.case_key},
                examiner_override=principal,
            )
        except Exception:
            pass

    def _case_from_row(self, row: Any) -> ActiveCase:
        case_id, case_key, title, description, status, artifact_path, metadata = row
        return ActiveCase(
            case_id=str(case_id),
            case_key=str(case_key),
            title=str(title),
            description=str(description) if description is not None else None,
            status=str(status),
            artifact_path=str(artifact_path) if artifact_path else None,
            metadata=dict(metadata or {}),
        )

    def _case_key_from_name(self, name: str) -> str:
        import datetime

        slug = re.sub(r"[^a-z0-9_-]+", "-", name.lower()).strip("-")
        slug = re.sub(r"-+", "-", slug) or "case"
        return f"{slug[:45]}-{datetime.datetime.utcnow().strftime('%Y%m%d-%H%M')}"
