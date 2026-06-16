"""Case metadata get/set with validation.

Owned by sift-core (Phase 2). Setting case metadata is *examiner-triggered*
in the portal (F-E) — it is not on the agent MCP surface. This module holds
the pure validation + persistence logic the portal route calls into.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping

import yaml

from sift_core.case_io import _atomic_write, load_case_meta

_MAX_FIELD = 500
_MAX_VALUE = 10_000

# BU2: banner stamped at the top of every DB->file CASE.yaml export so a human
# (or a tool) reading the file on disk cannot mistake it for authority.
_COMPAT_EXPORT_HEADER = (
    "# NON-AUTHORITATIVE COMPATIBILITY EXPORT — generated from the Postgres\n"
    "# control plane (app.cases). The database is the source of truth; edits to\n"
    "# this file are ignored by the gateway and overwritten on the next export.\n"
)

# -- Metadata validation tables --

ENUM_FIELDS: dict[str, set[str]] = {
    "incident_type": {
        "ransomware",
        "bec",
        "data_breach",
        "insider_threat",
        "supply_chain",
        "malware",
        "unauthorized_access",
        "dos",
        "other",
    },
    "severity": {"critical", "high", "medium", "low"},
    "tlp": {"WHITE", "GREEN", "AMBER", "AMBER+STRICT", "RED"},
}

DATE_FIELDS = {
    "detected_at",
    "occurred_at",
    "reported_at",
    "contained_at",
    "eradicated_at",
    "recovered_at",
}

LIST_FIELDS = {
    "affected_systems",
    "affected_accounts",
    "distribution_list",
    "tags",
    "related_cases",
}

# Identity/lifecycle fields managed by case creation/activation, never by the
# metadata setter.
PROTECTED_FIELDS = {
    "case_id",
    "status",
    "created",
    "examiner",
    "closed",
    "close_summary",
    "name",
    "description",
}

# Free text fields that accept any string value
TEXT_FIELDS = {"lead_examiner", "client", "point_of_contact", "impact_summary"}

ALLOWED_FIELDS = (
    PROTECTED_FIELDS | set(ENUM_FIELDS) | DATE_FIELDS | LIST_FIELDS | TEXT_FIELDS
)

# Settable (i.e. non-protected) fields, for caller-facing error messages/UI.
SETTABLE_FIELDS = ALLOWED_FIELDS - PROTECTED_FIELDS


def _validate_str_length(value: str | None, field: str, max_len: int) -> None:
    """Reject strings exceeding max_len or containing null bytes."""
    if value is not None and isinstance(value, str):
        if len(value) > max_len:
            raise ValueError(f"{field} exceeds maximum length of {max_len} characters")
        if "\x00" in value:
            raise ValueError(f"{field} contains invalid null byte")


def validate_iso8601(value: str) -> bool:
    """Check if value looks like an ISO 8601 datetime."""
    try:
        datetime.fromisoformat(value)
        return True
    except (ValueError, TypeError):
        return False


def get_case_metadata(case_dir: Path, field: str = "") -> dict:
    """Retrieve case metadata from CASE.yaml.

    If field is empty, returns all metadata. If field is specified, returns
    {"field": ..., "value": ...} (value is None if not set).
    """
    meta = load_case_meta(case_dir)
    if not field:
        return meta
    return {"field": field, "value": meta.get(field)}


def export_case_yaml_from_db(case_dir: Path, db_case: Mapping[str, Any]) -> dict:
    """BU2: write CASE.yaml as a NON-AUTHORITATIVE DB->file compatibility export.

    ``db_case`` is the gateway ``ActiveCase.as_dict()`` (DB authority): ``case_key``
    / ``title`` / ``description`` / ``status`` columns plus a ``metadata`` JSONB blob
    carrying the examiner identity and case-brief intake fields. This projects that
    row back into the legacy CASE.yaml shape, stamps a non-authoritative banner +
    ``compat_export`` marker, and writes it atomically. It never reads or merges the
    existing file (the DB row is the sole source), so a tampered CASE.yaml cannot
    survive an export. Returns the metadata dict that was written.
    """
    from sift_core.investigation_store import _DB_STATUS_TO_CASE_YAML

    meta: dict[str, Any] = dict(db_case.get("metadata") or {})
    case_key = db_case.get("case_key") or db_case.get("case_id")
    if case_key:
        meta["case_id"] = str(case_key)
    title = db_case.get("title") or db_case.get("name")
    if title is not None:
        meta["name"] = str(title)
    description = db_case.get("description")
    if description is not None:
        meta["description"] = str(description)
    raw_status = db_case.get("status")
    if raw_status is not None:
        meta["status"] = _DB_STATUS_TO_CASE_YAML.get(str(raw_status), str(raw_status))
    # Strip any stale authority/marker keys the JSONB might carry, then stamp ours.
    meta.pop("compat_export", None)
    meta["compat_export"] = {
        "authoritative": False,
        "source": "postgres",
        "exported_at": datetime.now(timezone.utc).isoformat(),
    }

    body = yaml.dump(meta, default_flow_style=False, sort_keys=True)
    _atomic_write(case_dir / "CASE.yaml", _COMPAT_EXPORT_HEADER + body)
    return meta


def set_case_metadata(case_dir: Path, field: str, value: str | list = "") -> dict:
    """Set a single metadata field in CASE.yaml.

    File-mode only (legacy / no control-plane DSN). In DB-authority deployments
    the portal writes ``app.cases`` and CASE.yaml is produced by
    :func:`export_case_yaml_from_db`; this setter is not the authority path.

    Validated fields: incident_type, severity, tlp (enums); detected_at,
    occurred_at, etc. (ISO 8601 dates); affected_systems, tags, etc. (lists).
    Protected fields (case_id, status, name, ...) are rejected. Unknown fields
    are rejected with the list of valid options.

    Returns {"status": "set", "field": ..., "value": ...} on success, or
    {"error": ...} on a validation failure.
    """
    _validate_str_length(field, "field", _MAX_FIELD)
    if isinstance(value, str):
        _validate_str_length(value, "value", _MAX_VALUE)

    if field in PROTECTED_FIELDS:
        return {
            "error": f"Field '{field}' is protected and cannot be set via this "
            f"tool. Protected fields: {', '.join(sorted(PROTECTED_FIELDS))}"
        }

    # Validate enum fields (case-insensitive for TLP)
    if field in ENUM_FIELDS:
        valid = ENUM_FIELDS[field]
        check_val = value
        # TLP is uppercase by convention
        if field == "tlp" and isinstance(value, str):
            check_val = value.upper()
        if check_val not in valid:
            return {
                "error": f"Invalid value for {field}: {value}. "
                f"Valid values: {', '.join(sorted(valid))}"
            }
        value = check_val

    # Validate date fields
    if field in DATE_FIELDS:
        if not isinstance(value, str) or not validate_iso8601(value):
            return {"error": f"Field '{field}' requires an ISO 8601 datetime string."}

    # Validate list fields
    if field in LIST_FIELDS:
        if not isinstance(value, list):
            return {
                "error": f"Field '{field}' requires a JSON array. "
                f'Example: ["{field}_item1", "{field}_item2"]'
            }

    # Reject unknown fields
    if field not in ALLOWED_FIELDS:
        return {
            "error": f"Unknown metadata field: '{field}'. "
            f"Allowed fields: {sorted(SETTABLE_FIELDS)}"
        }

    meta_file = case_dir / "CASE.yaml"
    meta = load_case_meta(case_dir)
    meta[field] = value
    _atomic_write(meta_file, yaml.dump(meta, default_flow_style=False))

    return {"status": "set", "field": field, "value": value}
