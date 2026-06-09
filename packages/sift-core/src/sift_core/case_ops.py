"""Case lifecycle operations: init, activate, list, status.

Pure-data functions (no CLI output). Called by the core case tools and the SIFT CLI.
"""

from __future__ import annotations

import json
import logging
import os
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

import yaml

from sift_core.case_io import (
    _atomic_write,
    case_audit_dir,
    cases_root,
    _tmp_case,
    load_findings,
    load_timeline,
    load_todos,
)
from sift_core.evidence_chain import init_evidence_chain

logger = logging.getLogger(__name__)

# Curated case-intake fields surfaced to the agent as the "case brief" so an
# autonomous investigator is grounded in scope + objectives (D-008). These mirror
# the examiner-settable schema in ``case_metadata`` plus the at-creation
# ``description``. Order is presentation order; only non-empty values are emitted.
CASE_BRIEF_FIELDS = (
    "description",
    "incident_type",
    "severity",
    "tlp",
    "client",
    "point_of_contact",
    "impact_summary",
    "detected_at",
    "occurred_at",
    "reported_at",
    "contained_at",
    "eradicated_at",
    "recovered_at",
    "affected_systems",
    "affected_accounts",
    "tags",
    "related_cases",
)


def build_case_brief(meta: dict) -> dict:
    """Extract the non-empty case-intake fields from CASE.yaml metadata.

    Returns a curated brief (scope narrative + structured incident facts) for
    grounding the agent. Empty/missing fields are omitted so the agent only sees
    what the examiner actually recorded.
    """
    brief: dict = {}
    for key in CASE_BRIEF_FIELDS:
        val = meta.get(key)
        if val in (None, "", [], {}):
            continue
        brief[key] = val
    return brief


def _db_investigation_snapshot(case_dir: Path) -> tuple[list, list, list] | None:
    """Return (findings, timeline, todos) from DB authority, or None in file mode.

    AUT2-B6: ``case_info`` counters must agree with the DB-backed list tools
    (``list_existing_findings`` etc.), so in DB-active mode the status counters
    are sourced from ``app.investigation_*`` instead of the file mirror. Only
    used when the authority context targets this exact case dir; any failure
    falls back to the file mirror (orientation read, not a mutating path).
    """
    try:
        from sift_core.active_case_context import current_active_case
        from sift_core.investigation_store import resolve_investigation_store

        ctx = current_active_case()
        if ctx is None or not ctx.db_active or not ctx.case_id:
            return None
        if ctx.case_dir is not None:
            try:
                if Path(case_dir).resolve() != ctx.case_dir.resolve():
                    return None
            except OSError:
                return None
        store = resolve_investigation_store()
        if store is None:
            return None
        return (
            store.list_findings(ctx.case_id),
            store.list_timeline(ctx.case_id),
            store.list_todos(ctx.case_id),
        )
    except Exception as exc:  # pragma: no cover - defensive read path
        logger.warning("DB investigation snapshot unavailable, using files: %s", exc)
        return None


def case_status_data(case_dir) -> dict:
    """Return case status as structured data."""
    case_dir = Path(case_dir)
    meta_file = case_dir / "CASE.yaml"
    if not meta_file.exists():
        raise ValueError(f"Not a SIFT case directory: {case_dir}")

    with open(meta_file) as f:
        meta = yaml.safe_load(f) or {}

    counters_authority = "file"
    db_snapshot = _db_investigation_snapshot(case_dir)
    if db_snapshot is not None:
        findings, timeline, todos = db_snapshot
        counters_authority = "db"
    else:
        findings = load_findings(case_dir)
        timeline = load_timeline(case_dir)
        todos = load_todos(case_dir)

    draft_f = sum(1 for f in findings if f.get("status") == "DRAFT")
    approved_f = sum(1 for f in findings if f.get("status") == "APPROVED")
    draft_t = sum(1 for t in timeline if t.get("status") == "DRAFT")
    approved_t = sum(1 for t in timeline if t.get("status") == "APPROVED")
    open_todos = sum(1 for t in todos if t.get("status") == "open")

    return {
        "case_id": meta.get("case_id", case_dir.name),
        "name": meta.get("name", "(unnamed)"),
        "status": meta.get("status", "unknown"),
        "examiner": meta.get("examiner", "unknown"),
        "case_brief": build_case_brief(meta),
        "path": str(case_dir),
        "evidence_dir": str(case_dir / "evidence"),
        "extractions_dir": str(case_dir / "extractions"),
        "reports_dir": str(case_dir / "reports"),
        "audit_dir": str((case_dir / "audit") if _tmp_case(case_dir) else case_audit_dir(case_dir)),
        "agent_dir": str(case_dir / "agent"),
        "finding_count": len(findings),
        "finding_draft": draft_f,
        "finding_approved": approved_f,
        "timeline_count": len(timeline),
        "timeline_draft": draft_t,
        "timeline_approved": approved_t,
        "todo_open": open_todos,
        "todo_total": len(todos),
        # AUT2-B6: where the finding/timeline/todo counters were sourced from
        # ("db" = app.investigation_* authority, "file" = legacy JSON mirror).
        "counters_authority": counters_authority,
    }


# Backward-compat alias used by the core case tools
_case_status_data = case_status_data


def case_list_data(cases_dir=None) -> dict:
    """Return list of cases as structured data."""
    if cases_dir is None:
        cases_dir = cases_root()
    else:
        cases_dir = Path(cases_dir)

    if not cases_dir.is_dir():
        return {"cases": [], "cases_root": str(cases_dir)}

    # Determine active case from env var first, then legacy file
    active_case_dir_name = None
    active_case_dir = os.environ.get("SIFT_CASE_DIR", "").strip()
    if active_case_dir:
        active_case_dir_name = Path(active_case_dir).name
    else:
        # Legacy CLI fallback — not used in portal workflow
        active_case_file = Path.home() / ".sift" / "active_case"
        if active_case_file.exists():
            try:
                content = active_case_file.read_text().strip()
                if os.path.isabs(content):
                    active_case_dir_name = Path(content).name
                else:
                    active_case_dir_name = content
            except OSError:
                pass

    cases = []
    for entry in sorted(cases_dir.iterdir()):
        if not entry.is_dir():
            continue
        meta_file = entry / "CASE.yaml"
        if not meta_file.exists():
            continue
        try:
            with open(meta_file) as f:
                meta = yaml.safe_load(f) or {}
        except (OSError, yaml.YAMLError):
            meta = {}
        cases.append(
            {
                "id": meta.get("case_id", entry.name),
                "name": meta.get("name", ""),
                "status": meta.get("status", "unknown"),
                "active": entry.name == active_case_dir_name,
            }
        )
    return {
        "cases": cases,
        "cases_root": str(cases_dir),
        "active_case_dir": active_case_dir or None,
    }


# Backward-compat alias
_case_list_data = case_list_data


def case_init_data(
    name: str, examiner: str, description: str = "", cases_dir=None, case_id=None
) -> dict:
    """Create a new case and return structured data."""
    if cases_dir is None:
        cases_dir = cases_root()
    else:
        cases_dir = Path(cases_dir)

    if not examiner:
        raise ValueError("Cannot initialize case: examiner identity is empty.")

    ts = datetime.now(timezone.utc)
    if not case_id:
        case_id = f"INC-{ts.strftime('%Y')}-{ts.strftime('%m%d%H%M%S')}"
    else:
        if not re.match(r"^[a-zA-Z0-9][a-zA-Z0-9_-]{1,63}$", case_id):
            raise ValueError(
                "case_id must be alphanumeric with hyphens/underscores, "
                "start with letter/digit, 2-64 chars"
            )
    case_dir = cases_dir / case_id

    if case_dir.exists():
        raise ValueError(f"Case directory already exists: {case_dir}")

    case_dir.mkdir(parents=True)
    for subdir in ("evidence", "extractions", "reports", "agent"):
        (case_dir / subdir).mkdir()
    if _tmp_case(case_dir):
        (case_dir / "audit").mkdir()

    case_meta = {
        "case_id": case_id,
        "name": name,
        "description": description,
        "status": "open",
        "examiner": examiner,
        "created": ts.isoformat(),
    }
    _atomic_write(case_dir / "CASE.yaml", yaml.dump(case_meta, default_flow_style=False))

    for fname in ("findings.json", "timeline.json", "todos.json"):
        with open(case_dir / fname, "w") as f:
            f.write("[]")
            f.flush()
            os.fsync(f.fileno())
    with open(case_dir / "evidence.json", "w") as f:
        json.dump({"files": []}, f)
        f.flush()
        os.fsync(f.fileno())

    init_evidence_chain(case_dir)

    # Detect non-POSIX filesystems before trying chmod
    fs_warning = ""
    try:
        result = subprocess.run(
            ["stat", "-f", "-c", "%T", str(case_dir)],
            capture_output=True, text=True,
        )
        fs_type = result.stdout.strip().lower()
        if fs_type in {"fuseblk", "vfat", "exfat", "ntfs"}:
            fs_warning = (
                f"Filesystem ({fs_type}) does not support POSIX permissions. "
                "chmod 444 protection will not be enforced."
            )
    except (OSError, FileNotFoundError):
        pass

    if not fs_warning:
        for fname in ("findings.json", "timeline.json"):
            try:
                os.chmod(case_dir / fname, 0o444)
            except OSError:
                pass

    # Set active case pointer — Legacy CLI fallback write (portal sets SIFT_CASE_DIR)
    try:
        sift_dir = Path.home() / ".sift"
        sift_dir.mkdir(exist_ok=True)
        _atomic_write(sift_dir / "active_case", str(case_dir.resolve()))  # Legacy CLI fallback
    except OSError:
        pass

    result_dict: dict = {
        "case_id": case_id,
        "case_dir": str(case_dir),
        "examiner": examiner,
        "created": ts.isoformat(),
    }
    if fs_warning:
        result_dict["fs_warning"] = fs_warning
    return result_dict


# Backward-compat alias
_case_init_data = case_init_data


def case_activate_data(case_id: str, cases_dir=None) -> dict:
    """Activate a case and return structured data."""
    if cases_dir is None:
        cases_dir = cases_root()
    else:
        cases_dir = Path(cases_dir)

    if not case_id or ".." in case_id or "/" in case_id or "\\" in case_id:
        raise ValueError(f"Invalid case ID: {case_id}")

    case_dir = cases_dir / case_id
    if not case_dir.exists():
        raise ValueError(f"Case not found: {case_id}")

    sift_dir = Path.home() / ".sift"
    sift_dir.mkdir(exist_ok=True)
    _atomic_write(sift_dir / "active_case", str(case_dir.resolve()))  # Legacy CLI fallback

    return {"case_id": case_id, "case_dir": str(case_dir)}


# Backward-compat alias
_case_activate_data = case_activate_data


def _set_case_wintools_permissions(case_dir: Path) -> None:
    """No-op: windows-triage support has been dropped."""
    pass
