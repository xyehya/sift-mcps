"""Postgres-backed add-on MCP backend registry (D22A)."""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from sift_gateway.backends import create_backend, validate_manifest_contract
from sift_gateway.identity import Identity

logger = logging.getLogger(__name__)


_ENV_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_RAW_SECRET_KEYS = frozenset(
    {
        "bearer_token",
        "tls_cert",
        "env",
        "headers",
        "password",
        "secret",
        "api_key",
        "token",
        "raw_token",
        "plaintext_token",
    }
)
_CONNECTION_KEYS = frozenset(
    {
        "type",
        "manifest_path",
        "command",
        "args",
        "cwd",
        "url",
        "enabled",
        "bearer_token_env",
        "tls_cert_env",
        "env_refs",
    }
)


class BackendRegistryError(Exception):
    def __init__(self, reason: str, *, http_status: int = 400) -> None:
        super().__init__(reason)
        self.reason = reason
        self.http_status = http_status


@dataclass(frozen=True)
class BackendRegistryRecord:
    id: str
    name: str
    namespace: str
    transport: str
    tier: str | None
    enabled: bool
    connection: dict[str, Any]
    data_plane: dict[str, Any] | None
    default_case_scoped: bool | None
    manifest: dict[str, Any]
    manifest_source: str | None
    manifest_sha256: str
    health_status: str
    health_detail: str | None
    health_checked_at: datetime | None
    registered_by: str | None
    created_at: datetime
    updated_at: datetime

    def public_dict(self, *, started: bool, available: bool, pending_apply: bool) -> dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "type": self.transport,
            "transport": self.transport,
            "namespace": self.namespace,
            "tier": self.tier,
            "enabled": self.enabled,
            "started": started,
            "available": available,
            "pending_apply": pending_apply,
            # Derived/reference-plane metadata (BATCH-F1): surface whether the
            # backend is case-scoped and its data-plane dependencies (e.g.
            # OpenSearch declares its derived index/provenance plane) so the
            # portal/registry can show that derived planes carry no authority.
            "default_case_scoped": self.default_case_scoped,
            "data_plane": dict(self.data_plane) if self.data_plane else None,
            "connection": dict(self.connection),
            "manifest_source": self.manifest_source,
            "manifest_sha256": self.manifest_sha256,
            "health": {
                "status": self.health_status,
                "detail": self.health_detail,
                "checked_at": _dt_iso(self.health_checked_at),
            },
            "created_at": _dt_iso(self.created_at),
            "updated_at": _dt_iso(self.updated_at),
        }


def _connect(dsn: str):
    try:
        import psycopg
    except ImportError as exc:  # pragma: no cover - deployment env
        raise RuntimeError("psycopg is required for MCP backend registry access") from exc
    return psycopg.connect(dsn)


def _jsonb(value: dict[str, Any]):
    try:
        from psycopg.types.json import Jsonb
    except ImportError:  # pragma: no cover
        return value
    return Jsonb(value)


def _dt_iso(value: datetime | None) -> str | None:
    if value is None:
        return None
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.isoformat()


def manifest_sha256(manifest: dict[str, Any]) -> str:
    payload = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(payload).hexdigest()


@dataclass(frozen=True)
class ManifestDriftFinding:
    """A first-party backend whose on-disk manifest no longer matches the row
    registered in ``app.mcp_backends`` (B-MVP-032).

    ``registered_sha`` is the stale ``manifest_sha256`` the gateway is still
    serving; ``on_disk_sha`` is the sha of the current ``sift-backend.json`` on
    disk. When they differ the install is serving a stale snapshot and new
    manifest-declared features (e.g. ``safe_case_argument_names`` gaining
    ``case_dir``) are silently disabled until the backend is re-registered.
    """

    name: str
    registered_sha: str
    on_disk_sha: str
    detail: str | None = None

    @property
    def drifted(self) -> bool:
        return self.registered_sha != self.on_disk_sha


def detect_manifest_drift(
    records: list[Any],
    *,
    load_manifest: Any,
) -> list[ManifestDriftFinding]:
    """Compare each backend's registered manifest sha to its on-disk manifest.

    Pure decision logic — no DB access. ``records`` is any iterable of objects
    exposing ``name``, ``manifest_sha256``, ``connection`` and ``enabled``.
    ``load_manifest(name, connection)`` must return the on-disk manifest dict
    (loaded the same way registration loaded it) or ``None`` when no on-disk
    manifest source is resolvable (e.g. remote HTTP-only add-ons). Records with
    no resolvable on-disk manifest are skipped — they cannot drift locally.

    Only records whose recomputed on-disk sha differs from the registered sha
    are returned, so a fresh install (shas match) yields an empty list.
    """
    findings: list[ManifestDriftFinding] = []
    for record in records:
        name = getattr(record, "name", None)
        registered_sha = getattr(record, "manifest_sha256", None)
        connection = getattr(record, "connection", None)
        if not name or not registered_sha or not isinstance(connection, dict):
            continue
        try:
            manifest = load_manifest(name, connection)
        except Exception as exc:  # pragma: no cover - defensive; never block boot
            logger.debug("manifest-drift: could not load on-disk manifest for %s: %s", name, exc)
            continue
        if not isinstance(manifest, dict):
            # No locally-resolvable manifest source (remote add-on, library
            # add-on returning None, missing file). Cannot assess local drift.
            continue
        on_disk_sha = manifest_sha256(manifest)
        if on_disk_sha != str(registered_sha):
            findings.append(
                ManifestDriftFinding(
                    name=str(name),
                    registered_sha=str(registered_sha),
                    on_disk_sha=on_disk_sha,
                )
            )
    return findings


def log_manifest_drift(
    findings: list[ManifestDriftFinding], *, log: logging.Logger | None = None
) -> None:
    """Emit a clear WARNING per drifted backend (warn-and-surface, B-MVP-032).

    Warn-only by design: re-registering a backend is an authority-plane write
    that must stay an explicit operator action, so this never mutates the
    registry. The operator re-registers (portal / installer) to clear it.
    """
    log = log or logger
    for finding in findings:
        log.warning(
            "manifest-drift: backend '%s' on-disk sift-backend.json (sha256=%s) "
            "does not match the registered manifest the gateway is serving "
            "(sha256=%s). The install is serving a STALE manifest snapshot; "
            "manifest-declared features may be silently disabled. Re-register "
            "this backend (portal/installer) to pick up the on-disk manifest.",
            finding.name,
            finding.on_disk_sha,
            finding.registered_sha,
        )


def _principal_type(principal: Any) -> str | None:
    if isinstance(principal, Identity):
        return "operator" if principal.principal_type == "user" else principal.principal_type
    if isinstance(principal, dict):
        value = principal.get("principal_type")
        return str(value) if value else None
    return None


def _principal_id(principal: Any) -> str | None:
    if isinstance(principal, Identity):
        return principal.principal_id
    if isinstance(principal, dict):
        value = principal.get("principal_id")
        return str(value) if value else None
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


def _operator_id(principal: Any) -> str | None:
    if _principal_type(principal) != "operator":
        return None
    return _principal_id(principal)


def _validate_env_name(value: Any, *, field: str) -> str:
    if not isinstance(value, str) or not _ENV_NAME_RE.match(value):
        raise BackendRegistryError(f"{field} must be an environment variable name")
    return value


def normalize_connection_config(config: dict[str, Any]) -> dict[str, Any]:
    """Return DB-storable non-secret backend connection metadata.

    Legacy raw secret fields are rejected. Secrets may be referenced only by
    Gateway process environment variable names and are resolved at load time.
    """
    if not isinstance(config, dict):
        raise BackendRegistryError("backend config must be an object")
    unexpected_secret_keys = sorted(_RAW_SECRET_KEYS.intersection(config))
    if unexpected_secret_keys:
        raise BackendRegistryError(
            "raw backend secret fields are not accepted; use credential references"
        )

    transport = str(config.get("type") or "stdio")
    if transport not in {"stdio", "http"}:
        raise BackendRegistryError("backend type must be 'stdio' or 'http'")

    connection: dict[str, Any] = {"type": transport}
    for key in _CONNECTION_KEYS:
        if key in {"type", "enabled"} or key not in config:
            continue
        value = config[key]
        if key in {"bearer_token_env", "tls_cert_env"}:
            value = _validate_env_name(value, field=key)
        elif key == "env_refs":
            if not isinstance(value, dict):
                raise BackendRegistryError("env_refs must be an object")
            refs: dict[str, str] = {}
            for target, source in value.items():
                target_name = _validate_env_name(target, field="env_refs key")
                refs[target_name] = _validate_env_name(source, field=f"env_refs.{target_name}")
            value = refs
        elif key == "args":
            if not isinstance(value, list):
                raise BackendRegistryError("args must be a list")
            # B-MVP-035: strip each arg. A stray space pasted into the portal
            # register form (e.g. "--stdio ") must not be passed verbatim to the
            # spawned process where it can change argument parsing.
            value = [str(item).strip() for item in value]
        elif key in {"manifest_path", "command", "cwd", "url"}:
            # B-MVP-035: trim surrounding whitespace. A trailing space on a
            # registered stdio `command` reached spawn as a non-existent
            # executable path -> FileNotFoundError on backend start, which then
            # hung the aggregated tools/list (-32001) and degraded the whole MCP
            # surface. These are not secrets; secret material is referenced only
            # via *_env names and resolved at load time, so trimming here is safe.
            value = str(value).strip()
        connection[key] = value

    if transport == "stdio" and not connection.get("command"):
        raise BackendRegistryError("stdio backend requires command")
    if transport == "http" and not connection.get("url"):
        raise BackendRegistryError("http backend requires url")
    return connection


def resolve_runtime_config(connection: dict[str, Any], *, environ: dict[str, str] | None = None) -> dict[str, Any]:
    env_source = os.environ if environ is None else environ
    config = dict(connection)
    transport = str(config.get("type") or "stdio")
    config["type"] = transport

    bearer_token_env = config.pop("bearer_token_env", None)
    if bearer_token_env:
        config["bearer_token"] = _resolve_env_ref(str(bearer_token_env), env_source, "bearer_token_env")

    tls_cert_env = config.pop("tls_cert_env", None)
    if tls_cert_env:
        config["tls_cert"] = _resolve_env_ref(str(tls_cert_env), env_source, "tls_cert_env")

    env_refs = config.pop("env_refs", {}) or {}
    if env_refs:
        resolved_env: dict[str, str] = {}
        for target, source in env_refs.items():
            resolved_env[str(target)] = _resolve_env_ref(str(source), env_source, f"env_refs.{target}")
        config["env"] = resolved_env
    return config


def _resolve_env_ref(name: str, environ: dict[str, str], field: str) -> str:
    if name not in environ or environ[name] == "":
        raise BackendRegistryError(f"{field} references missing environment variable")
    return str(environ[name])


class McpBackendRegistry:
    def __init__(self, dsn: str, *, audit: Any | None = None) -> None:
        self._dsn = dsn
        self._audit = audit

    def _connect(self):
        return _connect(self._dsn)

    def list_backends(self) -> list[BackendRegistryRecord]:
        with self._connect() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    select id::text, name, namespace, transport, tier, enabled,
                           connection, data_plane, default_case_scoped, manifest,
                           manifest_source, manifest_sha256, health_status,
                           health_detail, health_checked_at,
                           registered_by::text, created_at, updated_at
                    from app.mcp_backends
                    order by name
                    """
                )
                return [self._record_from_row(row) for row in cur.fetchall()]

    def enabled_backends(self) -> list[BackendRegistryRecord]:
        return [record for record in self.list_backends() if record.enabled]

    def create_backend_instances(self) -> tuple[dict[str, Any], datetime | None]:
        backends: dict[str, Any] = {}
        records = self.list_backends()
        loaded_at = max((record.updated_at for record in records), default=None)
        for record in records:
            if not record.enabled:
                continue
            try:
                config = resolve_runtime_config(record.connection)
                backend = create_backend(record.name, config, manifest=record.manifest)
                backends[record.name] = backend
            except Exception as exc:
                logger.error("Failed to create DB-registered backend %s: %s", record.name, exc)
                self.update_health(record.name, "error", _safe_detail(str(exc)))
        return backends, loaded_at

    def check_manifest_drift(
        self, records: list[BackendRegistryRecord] | None = None
    ) -> list[ManifestDriftFinding]:
        """Detect & WARN on registered-vs-on-disk manifest drift (B-MVP-032).

        For each enabled backend with a resolvable on-disk manifest source, the
        on-disk ``sift-backend.json`` is loaded the same way registration loaded
        it and its sha is compared to the registered ``manifest_sha256``. On a
        mismatch a WARNING is emitted naming the backend and both shas. Never
        raises and never mutates the registry — safe to call from the boot path.
        """
        try:
            from sift_gateway.backends import load_and_validate_manifest
        except Exception as exc:  # pragma: no cover - import guard
            logger.debug("manifest-drift: manifest loader unavailable: %s", exc)
            return []

        def _load(name: str, connection: dict[str, Any]) -> dict[str, Any] | None:
            return load_and_validate_manifest(name, resolve_runtime_config(connection))

        try:
            if records is None:
                records = self.enabled_backends()
            findings = detect_manifest_drift(records, load_manifest=_load)
        except Exception as exc:  # pragma: no cover - never block boot on drift check
            logger.debug("manifest-drift: drift check skipped: %s", exc)
            return []
        log_manifest_drift(findings)
        return findings

    def register(
        self,
        *,
        name: str,
        config: dict[str, Any],
        manifest: dict[str, Any],
        actor: Any | None,
    ) -> BackendRegistryRecord:
        connection = normalize_connection_config(config)
        # The REST registration path loads manifests through
        # load_and_validate_manifest(), which resolves local instructions_path
        # against the source file. Re-validating cached manifests here would not
        # have that source path, so only direct unit-test callers without an
        # instructions_path get the contract check here.
        if not manifest.get("instructions_path"):
            validate_manifest_contract(manifest)
        transport = str(connection.get("type") or "stdio")
        namespace = str(manifest.get("namespace") or "")
        if not namespace:
            raise BackendRegistryError("manifest namespace is required")
        digest = manifest_sha256(manifest)
        source = connection.get("manifest_path")
        operator_id = _operator_id(actor)
        enabled = bool(config.get("enabled", True))
        data_plane = manifest.get("data_plane")
        default_case_scoped = manifest.get("default_case_scoped")
        tier = manifest.get("tier")

        with self._connect() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    insert into app.mcp_backends
                      (name, namespace, transport, tier, enabled, connection,
                       data_plane, default_case_scoped, manifest, manifest_source,
                       manifest_sha256, health_status, registered_by, updated_at)
                    values
                      (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, 'unknown', %s, now())
                    on conflict (name) do update
                      set namespace = excluded.namespace,
                          transport = excluded.transport,
                          tier = excluded.tier,
                          enabled = excluded.enabled,
                          connection = excluded.connection,
                          data_plane = excluded.data_plane,
                          default_case_scoped = excluded.default_case_scoped,
                          manifest = excluded.manifest,
                          manifest_source = excluded.manifest_source,
                          manifest_sha256 = excluded.manifest_sha256,
                          health_status = 'unknown',
                          health_detail = null,
                          health_checked_at = null,
                          registered_by = coalesce(excluded.registered_by, app.mcp_backends.registered_by),
                          updated_at = now()
                    returning id::text, name, namespace, transport, tier, enabled,
                              connection, data_plane, default_case_scoped, manifest,
                              manifest_source, manifest_sha256, health_status,
                              health_detail, health_checked_at, registered_by::text,
                              created_at, updated_at
                    """,
                    (
                        name,
                        namespace,
                        transport,
                        tier,
                        enabled,
                        _jsonb(connection),
                        _jsonb(data_plane) if isinstance(data_plane, dict) else None,
                        default_case_scoped if isinstance(default_case_scoped, bool) else None,
                        _jsonb(manifest),
                        str(source) if source else None,
                        digest,
                        operator_id,
                    ),
                )
                row = cur.fetchone()
                if row is None:
                    raise BackendRegistryError("backend_registration_failed", http_status=500)
                record = self._record_from_row(row)
                self._insert_audit(
                    cur,
                    event_type="mcp_backend.registered",
                    actor=actor,
                    status="success",
                    summary=f"registered backend {name}",
                    details={
                        "backend": name,
                        "namespace": namespace,
                        "transport": transport,
                        "enabled": enabled,
                        "manifest_sha256": digest,
                    },
                )
                conn.commit()
        self._notify_audit("mcp_backend.registered", actor, name)
        return record

    def set_enabled(self, name: str, enabled: bool, *, actor: Any | None = None) -> BackendRegistryRecord:
        with self._connect() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    update app.mcp_backends
                    set enabled = %s,
                        health_status = case when %s then health_status else 'disabled' end,
                        updated_at = now()
                    where name = %s
                    returning id::text, name, namespace, transport, tier, enabled,
                              connection, data_plane, default_case_scoped, manifest,
                              manifest_source, manifest_sha256, health_status,
                              health_detail, health_checked_at, registered_by::text,
                              created_at, updated_at
                    """,
                    (enabled, enabled, name),
                )
                row = cur.fetchone()
                if row is None:
                    raise BackendRegistryError("backend_not_found", http_status=404)
                record = self._record_from_row(row)
                self._insert_audit(
                    cur,
                    event_type="mcp_backend.enabled_changed",
                    actor=actor,
                    status="success",
                    summary=f"{'enabled' if enabled else 'disabled'} backend {name}",
                    details={"backend": name, "enabled": enabled},
                )
                conn.commit()
        self._notify_audit("mcp_backend.enabled_changed", actor, name)
        return record

    def unregister(self, name: str, *, actor: Any | None = None) -> None:
        with self._connect() as conn:
            with conn.cursor() as cur:
                cur.execute("delete from app.mcp_backends where name = %s", (name,))
                if cur.rowcount == 0:
                    raise BackendRegistryError("backend_not_found", http_status=404)
                self._insert_audit(
                    cur,
                    event_type="mcp_backend.unregistered",
                    actor=actor,
                    status="success",
                    summary=f"unregistered backend {name}",
                    details={"backend": name},
                )
                conn.commit()
        self._notify_audit("mcp_backend.unregistered", actor, name)

    def update_health(self, name: str, status: str, detail: str | None = None) -> None:
        with self._connect() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    update app.mcp_backends
                    set health_status = %s,
                        health_detail = %s,
                        health_checked_at = now()
                    where name = %s
                    """,
                    (status, _safe_detail(detail), name),
                )
                conn.commit()

    def _record_from_row(self, row: Any) -> BackendRegistryRecord:
        (
            record_id,
            name,
            namespace,
            transport,
            tier,
            enabled,
            connection,
            data_plane,
            default_case_scoped,
            manifest,
            manifest_source,
            manifest_sha256_value,
            health_status,
            health_detail,
            health_checked_at,
            registered_by,
            created_at,
            updated_at,
        ) = row
        return BackendRegistryRecord(
            id=str(record_id),
            name=str(name),
            namespace=str(namespace),
            transport=str(transport),
            tier=str(tier) if tier is not None else None,
            enabled=bool(enabled),
            connection=dict(connection or {}),
            data_plane=dict(data_plane) if isinstance(data_plane, dict) else None,
            default_case_scoped=default_case_scoped if isinstance(default_case_scoped, bool) else None,
            manifest=dict(manifest or {}),
            manifest_source=str(manifest_source) if manifest_source else None,
            manifest_sha256=str(manifest_sha256_value),
            health_status=str(health_status),
            health_detail=str(health_detail) if health_detail else None,
            health_checked_at=health_checked_at,
            registered_by=str(registered_by) if registered_by else None,
            created_at=created_at,
            updated_at=updated_at,
        )

    def _insert_audit(
        self,
        cur: Any,
        *,
        event_type: str,
        actor: Any | None,
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
        fields = ["event_type", "actor_type", "source", "status", "summary", "details"]
        values: list[Any] = [event_type, actor_type, "gateway_mcp_backend_registry", status, summary, _jsonb(details)]
        if actor_column and actor_id:
            fields.insert(2, actor_column)
            values.insert(2, actor_id)
        cur.execute(
            f"""
            insert into app.audit_events ({", ".join(fields)})
            values ({", ".join(["%s"] * len(values))})
            """,
            values,
        )

    def _notify_audit(self, event_type: str, actor: Any | None, backend: str) -> None:
        if self._audit is None:
            return
        try:
            principal = getattr(actor, "principal", None)
            if principal is None and isinstance(actor, dict):
                principal = actor.get("display_name") or actor.get("email")
            self._audit.log(
                tool=event_type,
                params={"backend": backend},
                result_summary="success",
                source="gateway_mcp_backend_registry",
                extra={"backend": backend},
                examiner_override=principal,
            )
        except Exception as exc:
            # Audit mirror is best-effort (Postgres is the authority); surface
            # the failure at debug without leaking params/principal.
            logger.debug("backend audit mirror write failed: %s", type(exc).__name__)


def _safe_detail(detail: str | None) -> str | None:
    if not detail:
        return None
    text = str(detail)
    for marker in _RAW_SECRET_KEYS:
        if marker in text:
            return "Backend credential reference validation failed."
    return text[:500]
