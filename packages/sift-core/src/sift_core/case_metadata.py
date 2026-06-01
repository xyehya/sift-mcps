"""Case metadata get/set with validation.

Owned by sift-core (Phase 2). Setting case metadata is *examiner-triggered*
in the portal (F-E) — it is not on the agent MCP surface. This module holds
the pure validation + persistence logic the portal route calls into.
"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path

import yaml

from sift_core.case_io import _atomic_write, load_case_meta

_MAX_FIELD = 500
_MAX_VALUE = 10_000

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


def set_case_metadata(case_dir: Path, field: str, value: str | list = "") -> dict:
    """Set a single metadata field in CASE.yaml.

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
