"""Case dashboard routes — Starlette sub-app for finding review."""

import getpass
import hashlib
import hmac as hmac_mod
import json
import logging
import os
import re
import secrets
import tempfile
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

import yaml
from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import FileResponse, JSONResponse, Response
from starlette.routing import Route

from agentir_core.approval_auth import (
    _load_password_entry as _load_pw_entry,
    _save_password_entry as _save_pw_entry,
    derive_auth_key,
)
from agentir_core.case_io import _protected_write, compute_content_hash
from agentir_core.verification import compute_hmac, write_ledger_entry
from case_dashboard.session_jwt import (
    COOKIE_NAME,
    COOKIE_PATH,
    COOKIE_SAME_SITE,
    generate_jwt,
    verify_jwt,
    revoke_jti,
)

logger = logging.getLogger(__name__)

_STATIC_DIR = Path(__file__).parent / "static"
_PASSWORDS_DIR = Path("/var/lib/agentir/passwords")

# Set by create_dashboard_v2_app() at startup from gateway.yaml config.
_SESSION_SECRET: str = ""
_SESSION_MAX_AGE: int = 28800
_API_KEYS: dict = {}

# Gateway config path and write lock — set by create_dashboard_v2_app().
# Needed for token lifecycle endpoints that must persist changes to gateway.yaml.
_GATEWAY_CONFIG_PATH: Path | None = None
_GATEWAY_CONFIG_LOCK = threading.Lock()

# Max delta file size (1 MB)
_MAX_DELTA_SIZE = 1_048_576

# Fields excluded from content hash (must match case_io.py _HASH_EXCLUDE_KEYS)
_HASH_EXCLUDE_KEYS = {
    "status",
    "approved_at",
    "approved_by",
    "rejected_at",
    "rejected_by",
    "rejection_reason",
    "examiner_notes",
    "examiner_modifications",
    "content_hash",
    "verification",
    "modified_at",
    "provenance",
    "provenance_warnings",
    "timeline_event_id",
    "source_evidence",
}

_VALID_DELTA_KEYS = {
    "id",
    "type",
    "action",
    "content_hash_at_review",
    "modifications",
    "rejection_reason",
    "note",
    "todo_description",
    "todo_priority",
}

_REQUIRED_DELTA_KEYS = {"id", "type", "action"}

# Editable fields for modifications (must match approve.py:681-695 exactly)
_DELTA_EDITABLE_FIELDS = {
    # Finding fields
    "title",
    "observation",
    "interpretation",
    "confidence",
    "confidence_justification",
    "mitre_ids",
    "iocs",
    "context",
    # Timeline event fields
    "timestamp",
    "description",
    "source",
    # IOC fields
    "tags",
}

# In-memory challenge store (gateway is single-process uvicorn)
_challenges: dict[str, dict] = {}  # challenge_id → {nonce, examiner, created_at}
_CHALLENGE_TTL = 30  # seconds
_MAX_COMMIT_ATTEMPTS = 3
_COMMIT_LOCKOUT_SECONDS = 900

# Login challenge store — separate from commit challenges (R2 namespace separation)
_login_challenges: dict[str, dict] = {}
_LOGIN_CHALLENGE_TTL = 30  # seconds
_MAX_LOGIN_ATTEMPTS = 5  # Phase 15c specifies 5 for login
_MAX_LOGIN_CHALLENGES = 200  # R6 total pool cap
_MAX_LOGIN_CHALLENGES_PER_EXAMINER = 5  # R6 per-examiner in-flight limit

_case_create_lock = threading.Lock()
_CASE_ID_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,39}$")



def _resolve_case_dir() -> Path | None:
    """Resolve case directory per-request.

    Priority: AGENTIR_CASE_DIR env var (set via gateway.yaml case.dir).
    Returns None if no case is active or directory lacks CASE.yaml.
    """
    from sift_common import resolve_case_dir

    d = resolve_case_dir()
    if not d:
        return None
    p = Path(d)
    return p if p.is_dir() and (p / "CASE.yaml").exists() else None


def _no_case_response() -> JSONResponse:
    return JSONResponse(
        {"error": "No active case. Set AGENTIR_CASE_DIR in gateway.yaml case.dir."},
        status_code=404,
    )


def _load_json(path: Path) -> list | dict | None:
    """Load a JSON file, return None on missing/corrupt."""
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        logger.warning("Corrupt JSON file: %s", path)
        return None
    except OSError as e:
        logger.warning("Failed to read %s: %s", path, e)
        return None


def _load_yaml(path: Path) -> dict | None:
    """Load a YAML file. Returns None if missing. Raises ValueError on corrupt/unreadable."""
    if not path.exists():
        return None
    try:
        with open(path, encoding="utf-8") as f:
            return yaml.safe_load(f) or {}
    except yaml.YAMLError as e:
        raise ValueError(f"Corrupt YAML: {path}: {e}") from e
    except OSError as e:
        raise ValueError(f"Cannot read YAML: {path}: {e}") from e


def _load_jsonl(path: Path) -> list[dict]:
    """Load a JSONL file, skipping corrupt lines."""
    if not path.exists():
        return []
    entries = []
    try:
        with open(path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    entries.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
    except OSError:
        pass
    return entries


def _verify_items(case_dir: Path, items: list[dict]) -> list[dict]:
    """Add computed verification field to each item (finding or timeline event).

    Reimplements content-hash comparison from case_io.py.
    Five states: confirmed, tampered, unverified, no approval record, draft.
    """
    approvals = _load_jsonl(case_dir / "approvals.jsonl")

    # Build lookup: item_id -> last approval record
    last_approval: dict[str, dict] = {}
    for record in approvals:
        item_id = record.get("item_id")
        if item_id:
            last_approval[item_id] = record

    results = []
    for f in items:
        result = dict(f)
        status = f.get("status", "DRAFT")
        fid = f.get("id", "")
        record = last_approval.get(fid)

        if status == "DRAFT":
            result["verification"] = "draft"
        elif record:
            if record.get("action") == status:
                recomputed = compute_content_hash(f)
                finding_hash = f.get("content_hash")
                approval_hash = record.get("content_hash")
                if (finding_hash and recomputed != finding_hash) or (
                    approval_hash and recomputed != approval_hash
                ):
                    result["verification"] = "tampered"
                elif finding_hash or approval_hash:
                    result["verification"] = "confirmed"
                else:
                    result["verification"] = "unverified"
            else:
                result["verification"] = "no approval record"
        else:
            result["verification"] = "no approval record"
        results.append(result)
    return results


# --- Commit helpers ---


_EXAMINER_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,19}$")


def _resolve_examiner(request: Request) -> str | None:
    """Get examiner from auth middleware state. R9: always use getattr, never direct access."""
    examiner = getattr(request.state, "examiner", None)
    if not examiner or examiner == "anonymous":
        return None
    if not _EXAMINER_RE.match(examiner):
        return None
    return examiner


def _require_examiner_role(request: Request) -> JSONResponse | None:
    """Return 403 unless the authenticated portal principal is an examiner."""
    if getattr(request.state, "role", None) != "examiner":
        return JSONResponse(
            {"error": "Examiner role required"},
            status_code=403,
        )
    return None


def _check_commit_lockout(examiner: str) -> str | None:
    """Returns error message if locked out, None if OK."""
    lockout_file = Path.home() / ".agentir" / ".password_lockout"
    try:
        data = json.loads(lockout_file.read_text())
    except (OSError, json.JSONDecodeError):
        return None
    failures = data.get(examiner, [])
    now = time.time()
    recent = sum(1 for t in failures if now - t < _COMMIT_LOCKOUT_SECONDS)
    if recent >= _MAX_COMMIT_ATTEMPTS:
        oldest = min(t for t in failures if now - t < _COMMIT_LOCKOUT_SECONDS)
        remaining = int(_COMMIT_LOCKOUT_SECONDS - (now - oldest))
        return f"Too many failed attempts. Try again in {max(remaining, 1)}s."
    return None


def _record_commit_failure(examiner: str) -> None:
    """Record a failed commit attempt to shared lockout file."""
    lockout_file = Path.home() / ".agentir" / ".password_lockout"
    lockout_file.parent.mkdir(parents=True, exist_ok=True)
    try:
        data = json.loads(lockout_file.read_text())
    except (OSError, json.JSONDecodeError):
        data = {}
    data.setdefault(examiner, []).append(time.time())
    fd, tmp = tempfile.mkstemp(dir=str(lockout_file.parent), suffix=".tmp")
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w") as f:
            json.dump(data, f)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, str(lockout_file))
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def _clear_commit_failures(examiner: str) -> None:
    """Clear failure count on successful commit."""
    lockout_file = Path.home() / ".agentir" / ".password_lockout"
    try:
        data = json.loads(lockout_file.read_text())
    except (OSError, json.JSONDecodeError):
        return
    if examiner in data:
        del data[examiner]
        fd, tmp = tempfile.mkstemp(dir=str(lockout_file.parent), suffix=".tmp")
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "w") as f:
                json.dump(data, f)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp, str(lockout_file))
        except BaseException:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise


def _commit_failure_count(examiner: str) -> int:
    """Count recent failures for examiner."""
    lockout_file = Path.home() / ".agentir" / ".password_lockout"
    try:
        data = json.loads(lockout_file.read_text())
    except (OSError, json.JSONDecodeError):
        return 0
    now = time.time()
    return sum(1 for t in data.get(examiner, []) if now - t < _COMMIT_LOCKOUT_SECONDS)


# Login lockout helpers — use "login:{examiner}" as the key (R2: separate namespace)

def _check_login_lockout(examiner: str) -> str | None:
    """Returns error message if login is locked out; None if OK. R2: login: namespace."""
    lockout_file = Path.home() / ".agentir" / ".password_lockout"
    try:
        data = json.loads(lockout_file.read_text())
    except (OSError, json.JSONDecodeError):
        return None
    key = f"login:{examiner}"
    failures = data.get(key, [])
    now = time.time()
    recent = sum(1 for t in failures if now - t < _COMMIT_LOCKOUT_SECONDS)
    if recent >= _MAX_LOGIN_ATTEMPTS:
        oldest = min(t for t in failures if now - t < _COMMIT_LOCKOUT_SECONDS)
        remaining = int(_COMMIT_LOCKOUT_SECONDS - (now - oldest))
        return f"Too many failed attempts. Try again in {max(remaining, 1)}s."
    return None


def _record_login_failure(examiner: str) -> None:
    """Record a failed login attempt under login:{examiner} key. R2."""
    _record_commit_failure(f"login:{examiner}")


def _clear_login_failures(examiner: str) -> None:
    """Clear login failure count on success. R2."""
    _clear_commit_failures(f"login:{examiner}")


def _login_failure_count(examiner: str) -> int:
    """Count recent login failures under login:{examiner} key. R2."""
    return _commit_failure_count(f"login:{examiner}")


def _must_reset_check(examiner: str) -> JSONResponse | None:
    """R1: Returns 403 if examiner must reset password; None if OK. Re-reads from disk."""
    entry = _load_pw_entry(_PASSWORDS_DIR, examiner)
    if entry and entry.get("must_reset_password"):
        return JSONResponse(
            {"error": "Password reset required before performing this action"},
            status_code=403,
        )
    return None


def _iso_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _apply_note(item: dict, note: str, identity: dict) -> None:
    """Apply an examiner note to an item (mirrors CLI approve.py:602-610)."""
    item.setdefault("examiner_notes", []).append(
        {
            "note": note,
            "by": identity["examiner"],
            "at": _iso_now(),
        }
    )


def _write_approval_log_entry(
    case_dir: Path,
    item_id: str,
    action: str,
    identity: dict,
    now: str,
    **kwargs: object,
) -> None:
    """Append to approvals.jsonl. Schema matches case_io.py:write_approval_log."""
    log_path = case_dir / "approvals.jsonl"
    entry = {
        "ts": now,
        "item_id": item_id,
        "action": action,
        "os_user": identity["os_user"],
        "examiner": identity["examiner"],
        "examiner_source": identity.get("examiner_source", ""),
        "mode": "dashboard",
    }
    if kwargs.get("reason"):
        entry["reason"] = kwargs["reason"]
    if kwargs.get("content_hash"):
        entry["content_hash"] = kwargs["content_hash"]
    if kwargs.get("stale_at_approval"):
        entry["stale_at_approval"] = True
    if kwargs.get("coupled_from"):
        entry["coupled_from"] = kwargs["coupled_from"]

    # Match CLI: chmod 644 → append → chmod 444
    try:
        if log_path.exists():
            os.chmod(str(log_path), 0o644)
    except OSError:
        pass
    try:
        with open(log_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry) + "\n")
            f.flush()
            os.fsync(f.fileno())
    except OSError:
        logger.warning("Failed to write approval log: %s", log_path)
    try:
        os.chmod(str(log_path), 0o444)
    except OSError:
        pass


def _apply_delta(case_dir: Path, examiner: str, derived_key: bytes) -> dict:
    """Apply pending delta. Returns summary dict.

    derived_key is the stored PBKDF2 hash bytes — same as derive_hmac_key()
    would produce from the raw password + salt.

    This is a faithful port of _review_mode (approve.py:806-1159).
    Every field name, key, and schema detail matches the CLI.

    Write ordering matches CLI exactly (approve.py:1066-1113):
    Step 1 (critical): Save findings.json + timeline.json
    Step 2 (best-effort): Write approval log entries
    Step 3 (best-effort): Write HMAC ledger entries
    """
    delta_path = case_dir / "pending-reviews.json"
    processing_path = case_dir / "pending-reviews.processing"

    # Crash recovery (mirrors CLI approve.py:811-826)
    if processing_path.exists():
        if delta_path.exists():
            processing_path.unlink()
        else:
            os.rename(str(processing_path), str(delta_path))

    if not delta_path.exists():
        raise ValueError("No pending reviews to commit")

    # Atomic lock: rename to .processing
    try:
        os.rename(str(delta_path), str(processing_path))
    except OSError as exc:
        raise ValueError("Another commit is in progress") from exc

    try:
        delta = json.loads(processing_path.read_text())
        items_list = delta.get("items", [])
        if not items_list:
            raise ValueError("No items in delta")

        # Resolve case_id from CASE.yaml (matches approve.py:428-440)
        case_id = ""
        meta_file = case_dir / "CASE.yaml"
        if meta_file.exists():
            try:
                meta = yaml.safe_load(meta_file.read_text()) or {}
                case_id = meta.get("case_id", "")
            except Exception:
                pass
        if not case_id:
            case_id = case_dir.name

        # Case ID validation (mirrors CLI approve.py:856-872)
        delta_case_id = delta.get("case_id", "")
        if delta_case_id and case_id and delta_case_id != case_id:
            raise ValueError(
                f"Delta case_id ({delta_case_id}) does not match "
                f"active case ({case_id})"
            )

        # Load current state
        findings = _load_json(case_dir / "findings.json") or []
        timeline = _load_json(case_dir / "timeline.json") or []
        iocs_path = case_dir / "iocs.json"
        iocs = (_load_json(iocs_path) or []) if iocs_path.exists() else []
        all_items = findings + timeline + iocs
        item_by_id = {item["id"]: item for item in all_items}

        identity = {
            "examiner": examiner,
            "examiner_source": "dashboard",
            "os_user": getpass.getuser(),
        }
        now = _iso_now()

        approved_count = 0
        rejected_count = 0
        edited_count = 0
        skipped: list[tuple[str, str]] = []
        errors: list[str] = []
        approved_items: list[dict] = []
        log_entries: list[tuple[str, str, dict]] = []

        # Categorize by action (mirrors CLI approve.py:919-930)
        approvals = [
            de for de in items_list if de.get("action", "").lower() == "approve"
        ]
        rejections = [
            de for de in items_list if de.get("action", "").lower() == "reject"
        ]
        edits = [de for de in items_list if de.get("action", "").lower() == "edit"]

        # --- Process approvals (mirrors approve.py:953-1003) ---
        for entry in approvals:
            item_id = entry.get("id", "")
            item = item_by_id.get(item_id)
            if item is None:
                skipped.append((item_id, "not found"))
                continue

            modifications = entry.get("modifications", {})
            pre_mod_hash = item.get("content_hash", "")

            # C5: Verify modification originals match current values
            mod_conflict = False
            for field, mod in modifications.items():
                current_val = item.get(field)
                original_val = mod.get("original")
                if current_val != original_val:
                    skipped.append((item_id, f"field '{field}' changed since review"))
                    mod_conflict = True
                    break
            if mod_conflict:
                continue

            # Apply modifications (only editable fields)
            if modifications:
                for field, mod in modifications.items():
                    if field not in _DELTA_EDITABLE_FIELDS:
                        continue
                    item[field] = mod.get("modified")
                    item.setdefault("examiner_modifications", {})[field] = {
                        "original": mod.get("original"),
                        "modified": mod.get("modified"),
                        "modified_by": examiner,
                        "modified_at": now,
                    }

            # Apply note
            note = entry.get("note")
            if note:
                _apply_note(item, note, identity)

            # Compute content hash AFTER modifications
            new_hash = compute_content_hash(item)
            item["content_hash"] = new_hash
            item["status"] = "APPROVED"
            item["approved_at"] = now
            item["approved_by"] = examiner
            item["modified_at"] = now
            if item_id.startswith("IOC-"):
                item["manually_reviewed"] = True
            approved_count += 1
            approved_items.append(item)

            ch_at_review = entry.get("content_hash_at_review")
            stale = bool(ch_at_review and ch_at_review != pre_mod_hash)

            log_entries.append(
                (
                    item_id,
                    "APPROVED",
                    {
                        "content_hash": new_hash,
                        "stale_at_approval": stale,
                    },
                )
            )

        # --- Process edits (mirrors approve.py:1005-1046) ---
        for entry in edits:
            item_id = entry.get("id", "")
            item = item_by_id.get(item_id)
            if item is None:
                skipped.append((item_id, "not found"))
                continue

            modifications = entry.get("modifications", {})
            if not modifications:
                continue

            # C5: Verify originals match
            mod_conflict = False
            for field, mod in modifications.items():
                current_val = item.get(field)
                original_val = mod.get("original")
                if current_val != original_val:
                    skipped.append((item_id, f"field '{field}' changed since review"))
                    mod_conflict = True
                    break
            if mod_conflict:
                continue

            for field, mod in modifications.items():
                if field not in _DELTA_EDITABLE_FIELDS:
                    continue
                item[field] = mod.get("modified")
                item.setdefault("examiner_modifications", {})[field] = {
                    "original": mod.get("original"),
                    "modified": mod.get("modified"),
                    "modified_by": examiner,
                    "modified_at": now,
                }

            new_hash = compute_content_hash(item)
            item["content_hash"] = new_hash
            item["modified_at"] = now
            edited_count += 1

            log_entries.append((item_id, "EDITED", {"content_hash": new_hash}))

        # --- Process rejections (mirrors approve.py:1048-1064) ---
        for entry in rejections:
            item_id = entry.get("id", "")
            item = item_by_id.get(item_id)
            if item is None:
                skipped.append((item_id, "not found"))
                continue

            reason = entry.get("rejection_reason", "") or entry.get("reason", "")
            item["status"] = "REJECTED"
            item["rejected_at"] = now
            item["rejected_by"] = examiner
            if reason:
                item["rejection_reason"] = reason
            if item_id.startswith("IOC-"):
                item["manually_reviewed"] = True
            item["modified_at"] = now
            rejected_count += 1

            log_entries.append((item_id, "REJECTED", {"reason": reason}))

        # --- Timeline approval coupling ---
        # Auto-created timeline events follow their finding's action
        for item in all_items:
            auto_from = item.get("auto_created_from", "")
            if not auto_from:
                continue
            # Only cascade if timeline event has not been manually edited
            if item.get("examiner_modifications"):
                continue
            # Find the source finding
            source = item_by_id.get(auto_from)
            if not source:
                continue
            if source.get("status") == "APPROVED" and item.get("status") != "APPROVED":
                item["status"] = "APPROVED"
                item["approved_at"] = now
                item["approved_by"] = examiner
                item["modified_at"] = now
                new_hash = compute_content_hash(item)
                item["content_hash"] = new_hash
                approved_count += 1
                approved_items.append(item)
                log_entries.append(
                    (
                        item["id"],
                        "APPROVED",
                        {"content_hash": new_hash, "coupled_from": auto_from},
                    )
                )
            elif (
                source.get("status") == "REJECTED" and item.get("status") != "REJECTED"
            ):
                item["status"] = "REJECTED"
                item["rejected_at"] = now
                item["rejected_by"] = examiner
                item["rejection_reason"] = "Source finding rejected"
                item["modified_at"] = now
                rejected_count += 1
                log_entries.append(
                    (
                        item["id"],
                        "REJECTED",
                        {
                            "reason": "Source finding rejected",
                            "coupled_from": auto_from,
                        },
                    )
                )

        # --- IOC approval coupling ---
        iocs_modified = False
        for ioc in iocs:
            if ioc.get("manually_reviewed"):
                continue
            source_ids = ioc.get("source_findings", [])
            relevant = [
                item_by_id.get(sid) for sid in source_ids if item_by_id.get(sid)
            ]
            if not relevant:
                continue
            statuses = {r.get("status", "DRAFT") for r in relevant}
            if statuses == {"APPROVED"} and ioc.get("status") != "APPROVED":
                ioc["status"] = "APPROVED"
                ioc["approved_at"] = now
                ioc["approved_by"] = examiner
                ioc["modified_at"] = now
                iocs_modified = True
                approved_items.append(ioc)
                log_entries.append(
                    (
                        ioc["id"],
                        "APPROVED",
                        {
                            "content_hash": ioc.get("content_hash", ""),
                            "coupled_from": "ioc_cascade",
                        },
                    )
                )
            elif statuses == {"REJECTED"} and ioc.get("status") != "REJECTED":
                ioc["status"] = "REJECTED"
                ioc["rejected_at"] = now
                ioc["rejected_by"] = examiner
                ioc["rejection_reason"] = "All source findings rejected"
                ioc["modified_at"] = now
                iocs_modified = True
                log_entries.append(
                    (
                        ioc["id"],
                        "REJECTED",
                        {
                            "reason": "All source findings rejected",
                            "coupled_from": "ioc_cascade",
                        },
                    )
                )
            # Recompute confidence from non-rejected sources
            active = [r for r in relevant if r.get("status") != "REJECTED"]
            if active:
                conf_ranks = {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "SPECULATIVE": 3}
                best = min(
                    active,
                    key=lambda r: conf_ranks.get(
                        (r.get("confidence") or "").upper(), 99
                    ),
                )
                if best.get("confidence") != ioc.get("confidence"):
                    ioc["confidence"] = best["confidence"]
                    iocs_modified = True

        # ============================================================
        # Disk writes — CLI ordering (approve.py:1066-1113):
        # Step 1 (critical): Save primary data FIRST
        # Step 2 (best-effort): Approval log
        # Step 3 (best-effort): HMAC ledger
        # ============================================================

        # Step 1: Save findings + timeline + iocs
        _protected_write(case_dir / "findings.json", json.dumps(findings, indent=2, default=str))
        _protected_write(case_dir / "timeline.json", json.dumps(timeline, indent=2, default=str))
        # Save iocs if cascade modified OR any IOC was directly acted on
        any_ioc_acted = any(item_id.startswith("IOC-") for item_id, _, _ in log_entries)
        if iocs and (iocs_modified or any_ioc_acted):
            _protected_write(iocs_path, json.dumps(iocs, indent=2, default=str))

        # Step 2: Write approval log entries (best-effort)
        for item_id, action, kwargs in log_entries:
            _write_approval_log_entry(
                case_dir, item_id, action, identity, now, **kwargs
            )

        # Step 3: Write HMAC ledger entries (best-effort)
        hmac_failures: list[str] = []
        for item in approved_items:
            _item_id = item.get("id", "")
            _item_type = "timeline" if _item_id.startswith("T-") else "finding"
            _description = json.dumps(
                {k: v for k, v in item.items() if k not in _HASH_EXCLUDE_KEYS},
                sort_keys=True,
                default=str,
            )
            _mac = compute_hmac(derived_key, _description)
            _entry = {
                "finding_id": _item_id,
                "type": _item_type,
                "hmac": _mac,
                "hmac_version": 2,
                "content_snapshot": _description,
                "approved_by": examiner,
                "approved_at": now,
                "case_id": case_id,
                "mode": "dashboard",
            }
            try:
                write_ledger_entry(case_id, _entry)
            except OSError:
                logger.warning("HMAC write failed for %s", _item_id)
                hmac_failures.append(_item_id)

        # Delete processing file
        processing_path.unlink(missing_ok=True)

        return {
            "approved": approved_count,
            "rejected": rejected_count,
            "edited": edited_count,
            "skipped": [{"id": s[0], "reason": s[1]} for s in skipped],
            "errors": errors,
            "hmac_failures": hmac_failures,
        }
    except BaseException:
        # Restore delta file on failure
        try:
            if processing_path.exists() and not delta_path.exists():
                os.rename(str(processing_path), str(delta_path))
        except OSError:
            pass
        raise


# --- Endpoints ---


async def get_findings(request: Request) -> JSONResponse:
    case_dir = _resolve_case_dir()
    if not case_dir:
        return _no_case_response()
    findings = _load_json(case_dir / "findings.json") or []
    verified = _verify_items(case_dir, findings)
    return JSONResponse(verified)


async def get_finding_by_id(request: Request) -> JSONResponse:
    case_dir = _resolve_case_dir()
    if not case_dir:
        return _no_case_response()
    finding_id = request.path_params["id"]
    findings = _load_json(case_dir / "findings.json") or []
    verified = _verify_items(case_dir, findings)
    for f in verified:
        if f.get("id") == finding_id:
            return JSONResponse(f)
    return JSONResponse({"error": f"Finding {finding_id} not found"}, status_code=404)


async def get_timeline(request: Request) -> JSONResponse:
    case_dir = _resolve_case_dir()
    if not case_dir:
        return _no_case_response()
    timeline = _load_json(case_dir / "timeline.json") or []
    verified = _verify_items(case_dir, timeline)
    return JSONResponse(verified)


async def get_evidence(request: Request) -> JSONResponse:
    case_dir = _resolve_case_dir()
    if not case_dir:
        return _no_case_response()
    raw = _load_json(case_dir / "evidence.json")
    evidence = raw.get("files", []) if isinstance(raw, dict) else (raw or [])

    # Build referenced_by reverse index: evidence path → finding IDs
    findings = _load_json(case_dir / "findings.json") or []
    ref_index: dict[str, list[str]] = {}
    for f in findings:
        fid = f.get("id", "")
        if not fid:
            continue
        # Link via artifact source paths
        for art in f.get("artifacts", []):
            src = art.get("source", "")
            if src:
                ref_index.setdefault(src, []).append(fid)

    # Enrich evidence items
    for item in evidence:
        path = item.get("path", "")
        item["referenced_by"] = ref_index.get(path, [])

    return JSONResponse(evidence)


async def get_audit_for_finding(request: Request) -> JSONResponse:
    case_dir = _resolve_case_dir()
    if not case_dir:
        return _no_case_response()
    finding_id = request.path_params["finding_id"]

    # Get the finding's audit_ids
    findings = _load_json(case_dir / "findings.json") or []
    audit_ids: set[str] = set()
    for f in findings:
        if f.get("id") == finding_id:
            audit_ids = set(f.get("audit_ids", []))
            # Include provenance chain audit_ids for enriched rendering
            for art in f.get("artifacts", []):
                for step in art.get("provenance_chain", []):
                    if step.get("audit_id"):
                        audit_ids.add(step["audit_id"])
            break

    if not audit_ids:
        return JSONResponse([])

    # Scan audit/*.jsonl for matching audit_ids
    audit_dir = case_dir / "audit"
    if not audit_dir.is_dir():
        return JSONResponse([])

    matches = []
    for audit_file in sorted(audit_dir.glob("*.jsonl")):
        backend = audit_file.stem
        for entry in _load_jsonl(audit_file):
            entry_eid = entry.get("audit_id", "")
            if entry_eid in audit_ids:
                entry["_backend"] = backend
                matches.append(entry)

    return JSONResponse(matches)


async def get_delta(request: Request) -> JSONResponse:
    case_dir = _resolve_case_dir()
    if not case_dir:
        return _no_case_response()
    delta = _load_json(case_dir / "pending-reviews.json")
    if delta is None:
        return JSONResponse({"items": []})
    return JSONResponse(delta)


async def get_case(request: Request) -> JSONResponse:
    case_dir = _resolve_case_dir()
    if not case_dir:
        return _no_case_response()
    try:
        meta = _load_yaml(case_dir / "CASE.yaml")
    except ValueError as e:
        logger.error("Corrupt CASE.yaml: %s", e)
        return JSONResponse({"error": "Case metadata could not be read — check gateway logs"}, status_code=500)
    if meta is None:
        return JSONResponse({})
    return JSONResponse(meta)


async def get_todos(request: Request) -> JSONResponse:
    case_dir = _resolve_case_dir()
    if not case_dir:
        return _no_case_response()
    todos = _load_json(case_dir / "todos.json") or []
    return JSONResponse(todos)


async def get_iocs(request: Request) -> JSONResponse:
    case_dir = _resolve_case_dir()
    if not case_dir:
        return _no_case_response()
    iocs_path = case_dir / "iocs.json"
    if not iocs_path.exists():
        return JSONResponse([])
    return JSONResponse(_load_json(iocs_path) or [])


async def get_summary(request: Request) -> JSONResponse:
    case_dir = _resolve_case_dir()
    if not case_dir:
        return _no_case_response()

    findings = _load_json(case_dir / "findings.json") or []
    timeline = _load_json(case_dir / "timeline.json") or []
    raw_ev = _load_json(case_dir / "evidence.json")
    evidence = raw_ev.get("files", []) if isinstance(raw_ev, dict) else (raw_ev or [])
    todos = _load_json(case_dir / "todos.json") or []

    status_counts = {}
    for f in findings:
        s = f.get("status", "DRAFT")
        status_counts[s] = status_counts.get(s, 0) + 1

    timeline_counts = {}
    for t in timeline:
        s = t.get("status", "DRAFT")
        timeline_counts[s] = timeline_counts.get(s, 0) + 1

    open_todos = sum(1 for t in todos if t.get("status", "open") == "open")

    return JSONResponse(
        {
            "findings": {"total": len(findings), "by_status": status_counts},
            "timeline": {"total": len(timeline), "by_status": timeline_counts},
            "evidence": {"total": len(evidence)},
            "todos": {"total": len(todos), "open": open_todos},
        }
    )


async def post_delta(request: Request) -> JSONResponse:
    role_err = _require_examiner_role(request)
    if role_err:
        return role_err

    case_dir = _resolve_case_dir()
    if not case_dir:
        return _no_case_response()

    examiner = _resolve_examiner(request)
    if not examiner:
        return JSONResponse({"error": "Authentication required"}, status_code=401)
    err = _must_reset_check(examiner)
    if err:
        return err

    # Size check
    content_length = request.headers.get("content-length")
    try:
        if content_length and int(content_length) > _MAX_DELTA_SIZE:
            return JSONResponse(
                {"error": "Request body too large (max 1 MB)"},
                status_code=413,
            )
    except ValueError:
        pass

    body = await request.body()
    if len(body) > _MAX_DELTA_SIZE:
        return JSONResponse(
            {"error": "Request body too large (max 1 MB)"},
            status_code=413,
        )

    # Validate JSON
    try:
        data = json.loads(body)
    except json.JSONDecodeError:
        return JSONResponse({"error": "Invalid JSON"}, status_code=400)

    if not isinstance(data, dict):
        return JSONResponse({"error": "Expected JSON object"}, status_code=400)
    items = data.get("items")
    if items is not None and not isinstance(items, list):
        return JSONResponse({"error": "'items' must be a list"}, status_code=400)

    if items:
        for item in items:
            if not isinstance(item, dict):
                return JSONResponse(
                    {"error": "Each item must be a dict"}, status_code=400
                )
            unknown = set(item.keys()) - _VALID_DELTA_KEYS
            if unknown:
                return JSONResponse(
                    {
                        "error": f"Unknown fields in delta item: {', '.join(sorted(unknown))}"
                    },
                    status_code=400,
                )
            missing = _REQUIRED_DELTA_KEYS - set(item.keys())
            if missing:
                return JSONResponse(
                    {
                        "error": f"Missing required fields in delta item: {', '.join(sorted(missing))}"
                    },
                    status_code=400,
                )

    delta_path = case_dir / "pending-reviews.json"

    # Symlink protection
    if delta_path.exists() and os.path.islink(delta_path):
        return JSONResponse(
            {"error": "Refusing to write: target is a symlink"},
            status_code=403,
        )

    try:
        tmp_fd, tmp_path = tempfile.mkstemp(dir=str(case_dir), suffix=".tmp")
        try:
            with os.fdopen(tmp_fd, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp_path, str(delta_path))
        except Exception:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
            raise
    except OSError as e:
        logger.error("Failed to write delta file: %s", e)
        return JSONResponse({"error": "Write failed"}, status_code=500)

    return JSONResponse({"status": "ok"})


async def delete_delta_item(request: Request) -> JSONResponse:
    role_err = _require_examiner_role(request)
    if role_err:
        return role_err

    case_dir = _resolve_case_dir()
    if not case_dir:
        return _no_case_response()

    examiner = _resolve_examiner(request)
    if not examiner:
        return JSONResponse({"error": "Authentication required"}, status_code=401)
    err = _must_reset_check(examiner)
    if err:
        return err

    item_id = request.path_params["id"]
    delta_path = case_dir / "pending-reviews.json"

    # Symlink protection
    if delta_path.exists() and os.path.islink(delta_path):
        return JSONResponse(
            {"error": "Refusing to write: target is a symlink"},
            status_code=403,
        )

    delta = _load_json(delta_path)

    if delta is None or not isinstance(delta, dict):
        return JSONResponse({"error": "No delta file"}, status_code=404)

    items = delta.get("items", [])
    new_items = [i for i in items if i.get("id") != item_id]

    if len(new_items) == len(items):
        return JSONResponse(
            {"error": f"Item {item_id} not found in delta"},
            status_code=404,
        )

    delta["items"] = new_items
    try:
        tmp_fd, tmp_path = tempfile.mkstemp(dir=str(case_dir), suffix=".tmp")
        try:
            with os.fdopen(tmp_fd, "w", encoding="utf-8") as f:
                json.dump(delta, f, indent=2)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp_path, str(delta_path))
        except Exception:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
            raise
    except OSError as e:
        logger.error("Failed to write delta file: %s", e)
        return JSONResponse({"error": "Write failed"}, status_code=500)

    return JSONResponse({"status": "ok", "remaining": len(new_items)})


async def verify_evidence(request: Request) -> JSONResponse:
    role_err = _require_examiner_role(request)
    if role_err:
        return role_err

    case_dir = _resolve_case_dir()
    if not case_dir:
        return _no_case_response()

    examiner = _resolve_examiner(request)
    if not examiner:
        return JSONResponse({"error": "Authentication required"}, status_code=401)
    err = _must_reset_check(examiner)
    if err:
        return err

    req_path = request.path_params["path"]

    # Look up in evidence registry — the registry is the source of truth
    raw_ev = _load_json(case_dir / "evidence.json")
    evidence = raw_ev.get("files", []) if isinstance(raw_ev, dict) else (raw_ev or [])
    entry = None
    for item in evidence:
        if item.get("path") == req_path:
            entry = item
            break

    if entry is None:
        return JSONResponse(
            {"error": f"Not in evidence registry: {req_path}"},
            status_code=404,
        )

    stored_hash = entry.get("sha256", "")
    file_path = Path(entry["path"])

    # Path traversal protection on the registered path
    if ".." in str(file_path):
        return JSONResponse({"error": "Invalid path"}, status_code=400)

    if not file_path.is_file():
        return JSONResponse(
            {"error": f"File not found: {entry['path']}"},
            status_code=404,
        )

    # Hash the file
    h = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
    except OSError as e:
        logger.error("Cannot read evidence file %s: %s", file_path, e)
        return JSONResponse(
            {"error": "Cannot read file"},
            status_code=500,
        )
    computed_hash = h.hexdigest()

    match = computed_hash == stored_hash
    return JSONResponse(
        {
            "path": entry["path"],
            "computed_sha256": computed_hash,
            "stored_sha256": stored_hash,
            "status": "verified" if match else "failed",
        }
    )


async def get_commit_challenge(request: Request) -> JSONResponse:
    """Issue a challenge nonce + salt for password verification."""
    role_err = _require_examiner_role(request)
    if role_err:
        return role_err

    examiner = _resolve_examiner(request)
    if not examiner:
        return JSONResponse({"error": "No examiner identity"}, status_code=401)

    lockout_msg = _check_commit_lockout(examiner)
    if lockout_msg:
        return JSONResponse({"error": lockout_msg}, status_code=429)

    err = _must_reset_check(examiner)
    if err:
        return err

    entry = _load_pw_entry(_PASSWORDS_DIR, examiner)
    if not entry:
        return JSONResponse(
            {"error": "No password configured. Run: agentir config --setup-password"},
            status_code=403,
        )

    # Purge expired challenges
    now = time.time()
    expired = [
        k for k, v in _challenges.items() if now - v["created_at"] > _CHALLENGE_TTL
    ]
    for k in expired:
        del _challenges[k]

    challenge_id = secrets.token_hex(16)
    nonce = secrets.token_hex(32)
    _challenges[challenge_id] = {
        "nonce": nonce,
        "examiner": examiner,
        "created_at": now,
        "bound_ip": request.client.host,
    }

    return JSONResponse(
        {
            "challenge_id": challenge_id,
            "nonce": nonce,
            "salt": entry["salt"],
            "iterations": 600000,
            "hash_algorithm": "SHA-256",
        }
    )


async def post_commit(request: Request) -> JSONResponse:
    """Apply delta with challenge-response authentication."""
    role_err = _require_examiner_role(request)
    if role_err:
        return role_err

    case_dir = _resolve_case_dir()
    if not case_dir:
        return _no_case_response()

    examiner = _resolve_examiner(request)
    if not examiner:
        return JSONResponse({"error": "No examiner identity"}, status_code=401)

    lockout_msg = _check_commit_lockout(examiner)
    if lockout_msg:
        return JSONResponse({"error": lockout_msg}, status_code=429)

    err = _must_reset_check(examiner)
    if err:
        return err

    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"error": "Invalid JSON"}, status_code=400)

    challenge_id = body.get("challenge_id")
    response_hmac = body.get("response")

    if not challenge_id or not response_hmac:
        return JSONResponse(
            {"error": "Missing challenge_id or response"}, status_code=400
        )

    # Validate challenge
    challenge = _challenges.pop(challenge_id, None)
    if not challenge:
        return JSONResponse({"error": "Invalid or expired challenge"}, status_code=401)

    if challenge.get("bound_ip") != request.client.host:
        return JSONResponse({"error": "Challenge IP mismatch"}, status_code=403)

    now = time.time()
    if now - challenge["created_at"] > _CHALLENGE_TTL:
        return JSONResponse({"error": "Challenge expired"}, status_code=401)

    if challenge["examiner"] != examiner:
        return JSONResponse({"error": "Challenge/examiner mismatch"}, status_code=401)

    # Verify response: HMAC-SHA256(stored_pbkdf2_hash, nonce)
    entry = _load_pw_entry(_PASSWORDS_DIR, examiner)
    if not entry:
        return JSONResponse({"error": "No password configured"}, status_code=403)

    try:
        stored_hash = bytes.fromhex(entry["hash"])
    except (ValueError, KeyError):
        logger.error("Corrupt password entry for examiner %s", examiner)
        return JSONResponse({"error": "Password data corrupted"}, status_code=500)
    expected = hmac_mod.new(
        stored_hash, challenge["nonce"].encode(), "sha256"
    ).hexdigest()

    if not hmac_mod.compare_digest(expected, response_hmac):
        _record_commit_failure(examiner)
        remaining = _MAX_COMMIT_ATTEMPTS - _commit_failure_count(examiner)
        if remaining <= 0:
            msg = f"Too many failed attempts. Locked for {_COMMIT_LOCKOUT_SECONDS}s."
        else:
            msg = f"Incorrect password. {remaining} attempt(s) remaining."
        return JSONResponse({"error": msg}, status_code=401)

    _clear_commit_failures(examiner)

    # Apply delta (mirrors _review_mode)
    try:
        result = _apply_delta(case_dir, examiner, stored_hash)
    except Exception as e:
        logger.exception("Commit failed")
        return JSONResponse({"error": "Commit failed — check gateway logs"}, status_code=500)

    return JSONResponse(result)


# ---- Phase 12d: Auth endpoints ----


async def get_auth_setup_required(request: Request) -> JSONResponse:
    """No auth required. Returns whether first-time password setup is needed."""
    try:
        has_any = _PASSWORDS_DIR.is_dir() and any(_PASSWORDS_DIR.glob("*.json"))
    except OSError:
        has_any = False
    return JSONResponse({"required": not has_any})


async def post_auth_setup(request: Request) -> JSONResponse:
    """Create the first examiner account. Only available when no passwords exist."""
    try:
        already_set_up = _PASSWORDS_DIR.is_dir() and any(_PASSWORDS_DIR.glob("*.json"))
    except OSError:
        already_set_up = False
    if already_set_up:
        return JSONResponse({"error": "Already set up"}, status_code=409)

    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"error": "Invalid JSON"}, status_code=400)

    examiner = str(body.get("examiner", "")).strip()
    password = str(body.get("password", ""))

    if not _EXAMINER_RE.match(examiner):
        return JSONResponse({"error": "Invalid examiner name"}, status_code=400)
    if len(password) < 8:
        return JSONResponse(
            {"error": "Password too short (minimum 8 characters)"}, status_code=400
        )

    salt = secrets.token_bytes(32)
    pw_hash = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 600_000).hex()
    entry = {"hash": pw_hash, "salt": salt.hex(), "must_reset_password": False}
    try:
        _save_pw_entry(_PASSWORDS_DIR, examiner, entry)
    except PermissionError as e:
        logger.error("Cannot create passwords dir: %s", e)
        return JSONResponse(
            {"error": "Server configuration error — check gateway logs"},
            status_code=500,
        )
    except OSError:
        logger.exception("Failed to save password entry for %s", examiner)
        return JSONResponse(
            {"error": "Failed to save password — check gateway logs"},
            status_code=500,
        )
    return JSONResponse({"ok": True, "examiner": examiner})


async def get_auth_challenge(request: Request) -> JSONResponse:
    """Issue a login challenge nonce. Always returns 200 (R3: no user enumeration)."""
    examiner = str(request.query_params.get("examiner", "")).strip()
    if not examiner or not _EXAMINER_RE.match(examiner):
        return JSONResponse({"error": "Invalid examiner name"}, status_code=400)

    lockout_msg = _check_login_lockout(examiner)
    if lockout_msg:
        return JSONResponse({"error": lockout_msg}, status_code=429)

    entry = _load_pw_entry(_PASSWORDS_DIR, examiner)
    now = time.time()

    # Purge expired login challenges
    expired = [
        k for k, v in _login_challenges.items()
        if now - v["created_at"] > _LOGIN_CHALLENGE_TTL
    ]
    for k in expired:
        del _login_challenges[k]

    # R6: Per-examiner limit — evict oldest for this examiner if at cap
    per_examiner_keys = [
        k for k, v in _login_challenges.items() if v["examiner"] == examiner
    ]
    while len(per_examiner_keys) >= _MAX_LOGIN_CHALLENGES_PER_EXAMINER:
        oldest = min(per_examiner_keys, key=lambda k: _login_challenges[k]["created_at"])
        del _login_challenges[oldest]
        per_examiner_keys.remove(oldest)

    # R6: Total pool cap — evict oldest overall
    while len(_login_challenges) >= _MAX_LOGIN_CHALLENGES:
        oldest = min(
            _login_challenges.keys(), key=lambda k: _login_challenges[k]["created_at"]
        )
        del _login_challenges[oldest]

    # R3: Always issue a challenge — fake for unknown examiners
    is_fake = entry is None
    salt_hex = secrets.token_hex(32) if is_fake else entry["salt"]

    challenge_id = secrets.token_hex(16)
    nonce = secrets.token_hex(32)
    _login_challenges[challenge_id] = {
        "nonce": nonce,
        "examiner": examiner,
        "created_at": now,
        "bound_ip": request.client.host,
        "_fake": is_fake,
    }

    return JSONResponse(
        {
            "challenge_id": challenge_id,
            "nonce": nonce,
            "salt": salt_hex,
            "iterations": 600000,
            "hash_algorithm": "SHA-256",
        }
    )


async def post_auth_login(request: Request) -> JSONResponse:
    """Authenticate via PBKDF2 challenge-response. Sets session cookie on success."""
    if not _SESSION_SECRET:
        logger.error("Portal session secret not configured")
        return JSONResponse(
            {"error": "Portal session not configured — check gateway logs"},
            status_code=500,
        )

    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"error": "Invalid JSON"}, status_code=400)

    challenge_id = str(body.get("challenge_id", ""))
    examiner = str(body.get("examiner", "")).strip()
    response_hex = str(body.get("response", ""))

    if not challenge_id or not examiner or not response_hex:
        return JSONResponse({"error": "Missing required fields"}, status_code=400)

    if not _EXAMINER_RE.match(examiner):
        return JSONResponse({"error": "Invalid credentials"}, status_code=401)

    # R2: Check login lockout (login: namespace, separate from commit lockout)
    lockout_msg = _check_login_lockout(examiner)
    if lockout_msg:
        return JSONResponse({"error": lockout_msg}, status_code=429)

    # Pop challenge — single-use
    challenge = _login_challenges.pop(challenge_id, None)
    if not challenge:
        return JSONResponse({"error": "Invalid or expired challenge"}, status_code=401)

    now = time.time()
    if now - challenge["created_at"] > _LOGIN_CHALLENGE_TTL:
        return JSONResponse({"error": "Invalid credentials"}, status_code=401)

    if challenge.get("bound_ip") != request.client.host or challenge["examiner"] != examiner:
        return JSONResponse({"error": "Invalid credentials"}, status_code=401)

    # R3: Fake challenges always fail — same error path as real mismatch
    if challenge.get("_fake"):
        _record_login_failure(examiner)
        return JSONResponse({"error": "Invalid credentials"}, status_code=401)

    entry = _load_pw_entry(_PASSWORDS_DIR, examiner)
    if not entry:
        return JSONResponse({"error": "Invalid credentials"}, status_code=401)

    # R8: Domain-separated auth key — never use raw stored hash directly
    try:
        auth_key = derive_auth_key(entry["hash"])
    except (ValueError, KeyError):
        logger.error("Corrupt password entry for examiner %s", examiner)
        return JSONResponse(
            {"error": "Server configuration error — check gateway logs"},
            status_code=500,
        )

    expected = hmac_mod.new(auth_key, challenge["nonce"].encode(), "sha256").hexdigest()
    if not hmac_mod.compare_digest(expected, response_hex):
        _record_login_failure(examiner)
        remaining = _MAX_LOGIN_ATTEMPTS - _login_failure_count(examiner)
        msg = (
            f"Too many failed attempts. Locked for {_COMMIT_LOCKOUT_SECONDS}s."
            if remaining <= 0
            else "Invalid credentials"
        )
        return JSONResponse({"error": msg}, status_code=401)

    _clear_login_failures(examiner)

    must_reset = bool(entry.get("must_reset_password", False))
    role = entry.get("role", "examiner")

    token = generate_jwt(examiner, role, _SESSION_SECRET, _SESSION_MAX_AGE)
    exp_ts = int(time.time()) + _SESSION_MAX_AGE
    expires_at = datetime.fromtimestamp(exp_ts, tz=timezone.utc).isoformat()

    resp = JSONResponse(
        {
            "examiner": examiner,
            "role": role,
            "expires_at": expires_at,
            "must_reset": must_reset,
        }
    )
    resp.set_cookie(
        COOKIE_NAME,
        token,
        max_age=_SESSION_MAX_AGE,
        path=COOKIE_PATH,
        httponly=True,
        secure=True,
        samesite=COOKIE_SAME_SITE,
    )
    return resp


async def post_auth_reset_password(request: Request) -> JSONResponse:
    """Reset password via login challenge + new password. Clears must_reset_password."""
    examiner = _resolve_examiner(request)
    if not examiner:
        return JSONResponse({"error": "Authentication required"}, status_code=401)

    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"error": "Invalid JSON"}, status_code=400)

    challenge_id = str(body.get("challenge_id", ""))
    response_hex = str(body.get("response", ""))
    new_password = str(body.get("new_password", ""))

    if not challenge_id or not response_hex or not new_password:
        return JSONResponse({"error": "Missing required fields"}, status_code=400)

    if len(new_password) < 8:
        return JSONResponse(
            {"error": "Password too short (minimum 8 characters)"}, status_code=400
        )

    challenge = _login_challenges.pop(challenge_id, None)
    if not challenge:
        return JSONResponse({"error": "Invalid or expired challenge"}, status_code=401)

    now = time.time()
    if now - challenge["created_at"] > _LOGIN_CHALLENGE_TTL:
        return JSONResponse({"error": "Challenge expired"}, status_code=401)

    if challenge.get("_fake") or challenge["examiner"] != examiner:
        return JSONResponse({"error": "Invalid credentials"}, status_code=401)

    if challenge.get("bound_ip") != request.client.host:
        return JSONResponse({"error": "Challenge IP mismatch"}, status_code=401)

    entry = _load_pw_entry(_PASSWORDS_DIR, examiner)
    if not entry:
        return JSONResponse({"error": "No password configured"}, status_code=403)

    try:
        auth_key = derive_auth_key(entry["hash"])
    except (ValueError, KeyError):
        logger.error("Corrupt password entry for examiner %s", examiner)
        return JSONResponse(
            {"error": "Server configuration error — check gateway logs"},
            status_code=500,
        )

    expected = hmac_mod.new(auth_key, challenge["nonce"].encode(), "sha256").hexdigest()
    if not hmac_mod.compare_digest(expected, response_hex):
        return JSONResponse({"error": "Invalid credentials"}, status_code=401)

    new_salt = secrets.token_bytes(32)
    new_hash = hashlib.pbkdf2_hmac("sha256", new_password.encode(), new_salt, 600_000).hex()
    new_entry = {**entry, "hash": new_hash, "salt": new_salt.hex(), "must_reset_password": False}
    try:
        _save_pw_entry(_PASSWORDS_DIR, examiner, new_entry)
    except OSError:
        logger.exception("Failed to update password for %s", examiner)
        return JSONResponse(
            {"error": "Failed to update password — check gateway logs"},
            status_code=500,
        )
    return JSONResponse({"ok": True})


async def post_auth_logout(request: Request) -> JSONResponse:
    """Clear the portal session cookie and revoke the JTI."""
    cookie_token = request.cookies.get(COOKIE_NAME)
    if cookie_token and _SESSION_SECRET:
        payload = verify_jwt(cookie_token, _SESSION_SECRET)
        if payload and "jti" in payload:
            revoke_jti(payload["jti"])

    resp = JSONResponse({"ok": True})
    resp.set_cookie(
        COOKIE_NAME,
        "",
        max_age=0,
        path=COOKIE_PATH,
        httponly=True,
        secure=True,
        samesite=COOKIE_SAME_SITE,
    )
    return resp


async def get_auth_me(request: Request) -> JSONResponse:
    """Return current session info, or 401 if not authenticated."""
    examiner = getattr(request.state, "examiner", None)
    role = getattr(request.state, "role", None)

    if not examiner:
        return JSONResponse({"error": "Not authenticated"}, status_code=401)

    # R1: Re-read must_reset from disk — JWT is a UI hint only
    entry = _load_pw_entry(_PASSWORDS_DIR, examiner)
    must_reset = bool(entry.get("must_reset_password", False)) if entry else False

    cookie_val = request.cookies.get(COOKIE_NAME)
    expires_at = None
    if cookie_val and _SESSION_SECRET:
        payload = verify_jwt(cookie_val, _SESSION_SECRET)
        if payload:
            exp_ts = payload.get("exp", 0)
            expires_at = datetime.fromtimestamp(exp_ts, tz=timezone.utc).isoformat()

    return JSONResponse(
        {
            "examiner": examiner,
            "role": role,
            "expires_at": expires_at,
            "must_reset": must_reset,
        }
    )


async def serve_index(request: Request) -> Response:
    index_path = _STATIC_DIR / "index.html"
    if not index_path.exists():
        return JSONResponse(
            {"error": "Dashboard not built yet"},
            status_code=404,
        )
    return FileResponse(index_path, media_type="text/html")


_V2_STATIC_DIR = _STATIC_DIR / "v2"


async def serve_v2_index(request: Request) -> Response:
    index_path = _V2_STATIC_DIR / "index.html"
    if not index_path.exists():
        return JSONResponse(
            {"error": "Dashboard v2 not built yet"},
            status_code=404,
        )
    return FileResponse(index_path, media_type="text/html")


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        response = await call_next(request)
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Content-Security-Policy"] = (
            "default-src 'none'; "
            "script-src 'unsafe-inline'; "
            "style-src 'unsafe-inline'; "
            "img-src 'self'; "
            "connect-src 'self'"
        )
        return response


# ---------------------------------------------------------------------------
# Phase 13f — Service-token lifecycle
# ---------------------------------------------------------------------------

# Safe label pattern: printable ASCII, no shell-special or control characters.
_TOKEN_LABEL_RE = re.compile(r"^[\w\s.,:/@-]{1,80}$")
# agent_id pattern: lowercase alnum + hyphen/underscore, 1-64 chars.
_AGENT_ID_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")


def _token_config_write(updates: dict[str, dict | None]) -> None:
    """Atomically persist api_keys updates to gateway.yaml and _API_KEYS.

    ``updates`` maps raw_token → key_info dict (None = mark revoked_at).
    Caller must hold _GATEWAY_CONFIG_LOCK.

    Raises:
        RuntimeError: If gateway config path is not configured.
        OSError: If the disk write fails.
    """
    if _GATEWAY_CONFIG_PATH is None:
        raise RuntimeError("Gateway config path not configured")

    # Load current config from disk
    try:
        with open(_GATEWAY_CONFIG_PATH, encoding="utf-8") as f:
            import yaml as _yaml

            config = _yaml.safe_load(f) or {}
    except (OSError, Exception) as e:
        raise OSError(f"Cannot read gateway config: {e}") from e

    if "api_keys" not in config or not isinstance(config["api_keys"], dict):
        config["api_keys"] = {}

    # Apply updates
    for raw_token, info in updates.items():
        if info is None:
            # Should not happen — callers always pass a full dict
            continue
        config["api_keys"][raw_token] = info

    # Atomic write
    import yaml as _yaml

    config_dir = _GATEWAY_CONFIG_PATH.parent
    config_dir.mkdir(parents=True, exist_ok=True)
    fd, tmp_path = tempfile.mkstemp(dir=str(config_dir), suffix=".tmp")
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            _yaml.dump(config, f, default_flow_style=False, allow_unicode=True)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp_path, str(_GATEWAY_CONFIG_PATH))
    except BaseException:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise

    # Mirror to live in-memory dict so auth middleware sees new state immediately
    for raw_token, info in updates.items():
        _API_KEYS[raw_token] = info


def _token_metadata(info: dict) -> dict:
    """Return public metadata fields for a token; strip the raw token value."""
    return {
        "token_id": info.get("token_id", ""),
        "agent_id": info.get("agent_id"),
        "label": info.get("label", ""),
        "role": info.get("role", "agent"),
        "created_by": info.get("created_by"),
        "created_at": info.get("created_at"),
        "expires_at": info.get("expires_at"),
        "revoked_at": info.get("revoked_at"),
        "last_used_at": info.get("last_used_at"),
        "last_used_ip": info.get("last_used_ip"),
    }


async def list_tokens(request: Request) -> JSONResponse:
    """GET /api/tokens — list service token metadata. Examiner or readonly.

    Never returns raw token values.
    """
    examiner = getattr(request.state, "examiner", None)
    if not examiner:
        return JSONResponse({"error": "Authentication required"}, status_code=401)

    tokens = []
    for raw_token, info in _API_KEYS.items():
        if not isinstance(info, dict):
            continue
        if info.get("role") not in ("agent", "readonly"):
            continue  # Skip examiner gateway tokens from this view
        tokens.append(_token_metadata(info))

    # Sort by created_at for stable output
    tokens.sort(key=lambda t: t.get("created_at") or "")
    return JSONResponse({"tokens": tokens, "count": len(tokens)})


async def create_token(request: Request) -> JSONResponse:
    """POST /api/tokens — create a new agentir_svc_* service token.

    Required examiner role + must_reset check.
    Raw token value is returned exactly once and never stored in plaintext.

    Request body:
        agent_id: str     (required) — machine/agent identifier
        label: str        (required) — human description
        expires_at: str   (optional) — ISO datetime
        role: str         (optional) — "agent" (default) or "readonly"
    """
    role_err = _require_examiner_role(request)
    if role_err:
        return role_err

    examiner = _resolve_examiner(request)
    if not examiner:
        return JSONResponse({"error": "Authentication required"}, status_code=401)
    must_err = _must_reset_check(examiner)
    if must_err:
        return must_err

    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"error": "Invalid JSON"}, status_code=400)

    agent_id = str(body.get("agent_id", "")).strip()
    label = str(body.get("label", "")).strip()
    expires_at = body.get("expires_at")  # ISO string or null
    token_role = str(body.get("role", "agent")).strip()

    if not agent_id:
        return JSONResponse({"error": "agent_id is required"}, status_code=400)
    if not _AGENT_ID_RE.match(agent_id):
        return JSONResponse(
            {"error": "agent_id must match [a-z0-9][a-z0-9_-]{0,63}"},
            status_code=400,
        )
    if not label:
        return JSONResponse({"error": "label is required"}, status_code=400)
    if not _TOKEN_LABEL_RE.match(label):
        return JSONResponse({"error": "label contains disallowed characters"}, status_code=400)
    if token_role not in ("agent", "readonly"):
        return JSONResponse(
            {"error": "role must be 'agent' or 'readonly'"}, status_code=400
        )
    if expires_at is not None:
        try:
            datetime.fromisoformat(str(expires_at).replace("Z", "+00:00"))
        except ValueError:
            return JSONResponse({"error": "expires_at must be an ISO datetime"}, status_code=400)

    # Ensure agent_id is not already active (non-revoked)
    for info in _API_KEYS.values():
        if (
            isinstance(info, dict)
            and info.get("agent_id") == agent_id
            and not info.get("revoked_at")
        ):
            return JSONResponse(
                {"error": f"Active token already exists for agent_id '{agent_id}'"},
                status_code=409,
            )

    if _GATEWAY_CONFIG_PATH is None:
        return JSONResponse(
            {"error": "Token management unavailable: gateway config path not set"},
            status_code=503,
        )

    from sift_gateway.token_gen import generate_service_token

    raw_token = generate_service_token()
    token_id = f"svc-{agent_id}-{secrets.token_hex(4)}"
    now_iso = _iso_now()

    key_info: dict = {
        "token_id": token_id,
        "examiner": agent_id,  # used by auth middleware for audit identity
        "agent_id": agent_id,
        "role": token_role,
        "label": label,
        "created_by": examiner,
        "created_at": now_iso,
        "expires_at": expires_at,
        "revoked_at": None,
        "last_used_at": None,
        "last_used_ip": None,
    }

    try:
        with _GATEWAY_CONFIG_LOCK:
            _token_config_write({raw_token: key_info})
    except (OSError, RuntimeError) as e:
        logger.error("Failed to write token to gateway config: %s", e)
        return JSONResponse(
            {"error": "Failed to persist token — check gateway logs"},
            status_code=500,
        )

    logger.info(
        "Service token created: token_id=%s agent_id=%s by=%s", token_id, agent_id, examiner
    )
    return JSONResponse(
        {
            "ok": True,
            "token": raw_token,  # returned exactly once
            "token_id": token_id,
            "agent_id": agent_id,
            "role": token_role,
            "label": label,
            "created_at": now_iso,
            "expires_at": expires_at,
        },
        status_code=201,
    )


async def revoke_token(request: Request) -> JSONResponse:
    """DELETE /api/tokens/{token_id} — revoke a service token.

    Requires examiner role + must_reset check.
    Sets revoked_at; the token is immediately rejected by verify_api_key().
    """
    role_err = _require_examiner_role(request)
    if role_err:
        return role_err

    examiner = _resolve_examiner(request)
    if not examiner:
        return JSONResponse({"error": "Authentication required"}, status_code=401)
    must_err = _must_reset_check(examiner)
    if must_err:
        return must_err

    if _GATEWAY_CONFIG_PATH is None:
        return JSONResponse(
            {"error": "Token management unavailable: gateway config path not set"},
            status_code=503,
        )

    token_id = request.path_params["token_id"]

    # Find the matching raw token
    found_raw: str | None = None
    found_info: dict | None = None
    for raw_token, info in _API_KEYS.items():
        if isinstance(info, dict) and info.get("token_id") == token_id:
            found_raw = raw_token
            found_info = dict(info)
            break

    if found_raw is None:
        return JSONResponse({"error": "Token not found"}, status_code=404)

    if found_info.get("revoked_at"):
        return JSONResponse({"error": "Token already revoked"}, status_code=409)

    # Guard: do not allow revoking examiner (gateway) tokens from this endpoint
    if found_info.get("role") == "examiner":
        return JSONResponse(
            {"error": "Cannot revoke examiner tokens via this endpoint"},
            status_code=403,
        )

    found_info["revoked_at"] = _iso_now()

    try:
        with _GATEWAY_CONFIG_LOCK:
            _token_config_write({found_raw: found_info})
    except (OSError, RuntimeError) as e:
        logger.error("Failed to revoke token %s: %s", token_id, e)
        return JSONResponse(
            {"error": "Failed to revoke token — check gateway logs"},
            status_code=500,
        )

    logger.info("Service token revoked: token_id=%s by=%s", token_id, examiner)
    return JSONResponse({"ok": True, "token_id": token_id, "revoked_at": found_info["revoked_at"]})


async def rotate_token(request: Request) -> JSONResponse:
    """POST /api/tokens/{token_id}/rotate — revoke old token, issue replacement.

    Requires examiner role + must_reset check.
    Returns the new raw token exactly once. Old token is immediately revoked.
    """
    role_err = _require_examiner_role(request)
    if role_err:
        return role_err

    examiner = _resolve_examiner(request)
    if not examiner:
        return JSONResponse({"error": "Authentication required"}, status_code=401)
    must_err = _must_reset_check(examiner)
    if must_err:
        return must_err

    if _GATEWAY_CONFIG_PATH is None:
        return JSONResponse(
            {"error": "Token management unavailable: gateway config path not set"},
            status_code=503,
        )

    token_id = request.path_params["token_id"]

    # Find old token
    found_raw: str | None = None
    found_info: dict | None = None
    for raw_token, info in _API_KEYS.items():
        if isinstance(info, dict) and info.get("token_id") == token_id:
            found_raw = raw_token
            found_info = dict(info)
            break

    if found_raw is None:
        return JSONResponse({"error": "Token not found"}, status_code=404)

    if found_info.get("revoked_at"):
        return JSONResponse({"error": "Cannot rotate an already-revoked token"}, status_code=409)

    if found_info.get("role") == "examiner":
        return JSONResponse(
            {"error": "Cannot rotate examiner tokens via this endpoint"},
            status_code=403,
        )

    from sift_gateway.token_gen import generate_service_token

    now_iso = _iso_now()

    # Build revoked copy of old entry
    revoked_info = {**found_info, "revoked_at": now_iso}

    # Build new token with inherited metadata
    new_raw_token = generate_service_token()
    new_token_id = f"svc-{found_info.get('agent_id', 'unknown')}-{secrets.token_hex(4)}"
    new_info: dict = {
        "token_id": new_token_id,
        "examiner": found_info.get("examiner", found_info.get("agent_id", "unknown")),
        "agent_id": found_info.get("agent_id"),
        "role": found_info.get("role", "agent"),
        "label": found_info.get("label", ""),
        "created_by": examiner,
        "created_at": now_iso,
        "expires_at": found_info.get("expires_at"),
        "revoked_at": None,
        "last_used_at": None,
        "last_used_ip": None,
    }

    try:
        with _GATEWAY_CONFIG_LOCK:
            # Both writes in the same lock: revoke old + create new atomically on disk
            _token_config_write({found_raw: revoked_info, new_raw_token: new_info})
    except (OSError, RuntimeError) as e:
        logger.error("Failed to rotate token %s: %s", token_id, e)
        return JSONResponse(
            {"error": "Failed to rotate token — check gateway logs"},
            status_code=500,
        )

    logger.info(
        "Service token rotated: old_token_id=%s new_token_id=%s by=%s",
        token_id,
        new_token_id,
        examiner,
    )
    return JSONResponse(
        {
            "ok": True,
            "revoked_token_id": token_id,
            "token": new_raw_token,  # returned exactly once
            "token_id": new_token_id,
            "agent_id": new_info.get("agent_id"),
            "role": new_info.get("role"),
            "label": new_info.get("label"),
            "created_at": now_iso,
            "expires_at": new_info.get("expires_at"),
        },
        status_code=201,
    )


def _resolve_gateway(request: Request):
    """Retrieve gateway reference from application state."""
    root_app = request.scope.get("app")
    if root_app and hasattr(root_app, "state") and hasattr(root_app.state, "gateway"):
        return root_app.state.gateway
    if hasattr(request.app, "state") and hasattr(request.app.state, "gateway"):
        return request.app.state.gateway
    return None


def _case_config_write(case_dir: str) -> None:
    """Atomically update case.dir in gateway.yaml.
    
    Caller must hold _GATEWAY_CONFIG_LOCK.
    """
    if _GATEWAY_CONFIG_PATH is None:
        raise RuntimeError("Gateway config path not configured")

    try:
        with open(_GATEWAY_CONFIG_PATH, encoding="utf-8") as f:
            import yaml as _yaml
            config = _yaml.safe_load(f) or {}
    except (OSError, Exception) as e:
        raise OSError(f"Cannot read gateway config: {e}") from e

    if "case" not in config or not isinstance(config["case"], dict):
        config["case"] = {}
    config["case"]["dir"] = case_dir

    import yaml as _yaml
    config_dir = _GATEWAY_CONFIG_PATH.parent
    config_dir.mkdir(parents=True, exist_ok=True)
    fd, tmp_path = tempfile.mkstemp(dir=str(config_dir), suffix=".tmp")
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            _yaml.dump(config, f, default_flow_style=False, allow_unicode=True)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp_path, str(_GATEWAY_CONFIG_PATH))
    except BaseException:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise


async def post_case_create(request: Request) -> JSONResponse:
    """POST /portal/api/case/create — Create a new case.

    Requires examiner role + must_reset check.
    Uses R5 symlink escape guard and threading lock concurrency guard.
    """
    examiner = _resolve_examiner(request)
    if not examiner:
        return JSONResponse({"error": "Authentication required"}, status_code=401)

    role_err = _require_examiner_role(request)
    if role_err:
        return role_err
    
    err = _must_reset_check(examiner)
    if err:
        return err

    try:
        body = await request.json()
    except json.JSONDecodeError:
        return JSONResponse({"error": "Invalid JSON"}, status_code=400)

    if not isinstance(body, dict):
        return JSONResponse({"error": "Expected JSON object"}, status_code=400)

    case_id = body.get("case_id", "").strip()
    title = body.get("title", "").strip()
    requested_dir = body.get("dir", "").strip()

    if not case_id or not title or not requested_dir:
        return JSONResponse({"error": "Missing required fields"}, status_code=400)

    if not _CASE_ID_RE.match(case_id):
        return JSONResponse({"error": "Invalid case_id format"}, status_code=400)

    # Determine case_root
    case_root = None
    if _GATEWAY_CONFIG_PATH is not None:
        try:
            with open(_GATEWAY_CONFIG_PATH, encoding="utf-8") as f:
                import yaml as _yaml
                config = _yaml.safe_load(f) or {}
            case_root = config.get("case", {}).get("root")
        except Exception:
            pass
    
    if not case_root:
        case_root = os.environ.get("AGENTIR_CASE_ROOT") or "/cases"

    # Interpolate environment variables in case_root
    case_root = re.sub(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}", lambda m: os.environ.get(m.group(1), ""), case_root)

    # R5 Symlink escape check
    real_root = Path(os.path.realpath(case_root))
    real_requested = Path(os.path.realpath(requested_dir))
    if not str(real_requested).startswith(str(real_root) + os.sep):
        return JSONResponse({"error": "Directory must be under case root"}, status_code=400)

    # Concurrency serialization using threading.Lock with non-blocking acquire
    acquired = _case_create_lock.acquire(blocking=False)
    if not acquired:
        return JSONResponse({"error": "Another case creation is in progress"}, status_code=409)

    try:
        if real_requested.exists():
            return JSONResponse({"error": "Case directory already exists"}, status_code=409)

        # Create directories
        real_requested.mkdir(parents=True)
        for subdir in ("audit", "evidence", "extractions", "reports"):
            (real_requested / subdir).mkdir()

        # Write CASE.yaml metadata
        ts = datetime.now(timezone.utc)
        case_meta = {
            "case_id": case_id,
            "name": title,
            "title": title,
            "status": "open",
            "examiner": examiner,
            "created": ts.isoformat(),
        }
        
        tmp_fd, tmp_yaml = tempfile.mkstemp(dir=str(real_requested), suffix=".tmp")
        try:
            with os.fdopen(tmp_fd, "w", encoding="utf-8") as f:
                yaml.safe_dump(case_meta, f, default_flow_style=False)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp_yaml, str(real_requested / "CASE.yaml"))
        except Exception:
            try:
                os.unlink(tmp_yaml)
            except OSError:
                pass
            raise

        # Initialize JSON/JSONL files
        for fname, content in [
            ("findings.json", "[]"),
            ("timeline.json", "[]"),
            ("evidence.json", '{"files": []}'),
            ("evidence-manifest.json", '{"version": 1, "sealed": false, "files": []}'),
            ("evidence-ledger.jsonl", ""),
            ("todos.json", "[]"),
            ("iocs.json", "[]"),
            ("approvals.jsonl", ""),
        ]:
            path = real_requested / fname
            with open(path, "w", encoding="utf-8") as f:
                f.write(content)
                f.flush()
                os.fsync(f.fileno())

        # Update gateway.yaml config atomically if configured
        if _GATEWAY_CONFIG_PATH is not None:
            try:
                with _GATEWAY_CONFIG_LOCK:
                    _case_config_write(str(real_requested))
            except Exception as e:
                logger.error("Failed to update gateway config with case dir: %s", e)
                return JSONResponse({"error": "Failed to update gateway config"}, status_code=500)

        # Update environment variable in-process
        os.environ["AGENTIR_CASE_DIR"] = str(real_requested)

        # Restart backends
        gateway = _resolve_gateway(request)
        if gateway:
            if hasattr(gateway, "config") and isinstance(gateway.config, dict):
                if "case" not in gateway.config:
                    gateway.config["case"] = {}
                gateway.config["case"]["dir"] = str(real_requested)
            
            if hasattr(gateway, "restart_backends"):
                await gateway.restart_backends()

        return JSONResponse({"ok": True, "case_dir": str(real_requested)})

    except Exception as e:
        logger.error("Failed to create case: %s", e)
        return JSONResponse({"error": "Internal server error during case creation"}, status_code=500)
    finally:
        _case_create_lock.release()


def _dashboard_api_routes() -> list[Route]:
    """API routes shared by v1 and v2 dashboard apps."""
    return [
        Route("/api/findings", get_findings, methods=["GET"]),
        Route("/api/findings/{id}", get_finding_by_id, methods=["GET"]),
        Route("/api/timeline", get_timeline, methods=["GET"]),
        Route("/api/evidence", get_evidence, methods=["GET"]),
        Route("/api/audit/{finding_id}", get_audit_for_finding, methods=["GET"]),
        Route("/api/delta", get_delta, methods=["GET"]),
        Route("/api/delta", post_delta, methods=["POST"]),
        Route("/api/delta/{id}", delete_delta_item, methods=["DELETE"]),
        Route("/api/case", get_case, methods=["GET"]),
        Route("/api/todos", get_todos, methods=["GET"]),
        Route("/api/iocs", get_iocs, methods=["GET"]),
        Route("/api/summary", get_summary, methods=["GET"]),
        Route("/api/evidence/{path:path}/verify", verify_evidence, methods=["POST"]),
        Route("/api/commit/challenge", get_commit_challenge, methods=["GET"]),
        Route("/api/commit", post_commit, methods=["POST"]),
        # Phase 12d: auth endpoints
        Route("/api/auth/setup-required", get_auth_setup_required, methods=["GET"]),
        Route("/api/auth/setup", post_auth_setup, methods=["POST"]),
        Route("/api/auth/challenge", get_auth_challenge, methods=["GET"]),
        Route("/api/auth/login", post_auth_login, methods=["POST"]),
        Route("/api/auth/reset-password", post_auth_reset_password, methods=["POST"]),
        Route("/api/auth/logout", post_auth_logout, methods=["POST"]),
        Route("/api/auth/me", get_auth_me, methods=["GET"]),
        # Phase 13f: service-token lifecycle
        Route("/api/tokens", list_tokens, methods=["GET"]),
        Route("/api/tokens", create_token, methods=["POST"]),
        Route("/api/tokens/{token_id}", revoke_token, methods=["DELETE"]),
        Route("/api/tokens/{token_id}/rotate", rotate_token, methods=["POST"]),
        Route("/api/case/create", post_case_create, methods=["POST"]),
    ]



def create_dashboard_app() -> Starlette:
    """Create the v1 dashboard sub-app for mounting on the gateway."""
    routes = _dashboard_api_routes()
    routes.append(Route("/", serve_index, methods=["GET"]))
    return Starlette(routes=routes, middleware=[Middleware(SecurityHeadersMiddleware)])


async def serve_v2_static(request: Request) -> Response:
    """Serve static files from the v2 directory (images, icons, etc.)."""
    filename = request.path_params.get("filename", "")
    if not filename or ".." in filename or "/" in filename or "\\" in filename:
        return JSONResponse({"error": "not found"}, status_code=404)
    allowed_ext = {".png", ".jpg", ".svg", ".ico", ".css", ".js"}
    if Path(filename).suffix.lower() not in allowed_ext:
        return JSONResponse({"error": "not found"}, status_code=404)
    file_path = _V2_STATIC_DIR / filename
    if not file_path.is_file():
        return JSONResponse({"error": "not found"}, status_code=404)
    media_types = {
        ".png": "image/png",
        ".jpg": "image/jpeg",
        ".svg": "image/svg+xml",
        ".ico": "image/x-icon",
        ".css": "text/css",
        ".js": "application/javascript",
    }
    return FileResponse(
        file_path,
        media_type=media_types.get(
            Path(filename).suffix.lower(), "application/octet-stream"
        ),
    )


def create_dashboard_v2_app(
    session_secret: str = "",
    session_max_age: int = 28800,
    api_keys: dict | None = None,
    gateway_config_path: str | None = None,
) -> Starlette:
    """Create the v2 dashboard sub-app for mounting on the gateway.

    Args:
        session_secret: JWT signing secret from portal.session_secret.
        session_max_age: Session lifetime in seconds (default 8 h).
        api_keys: Reference to the live gateway api_keys dict. Token lifecycle
            endpoints mutate this dict in place so changes are immediately
            honoured by the auth middleware without a restart.
        gateway_config_path: Absolute path to gateway.yaml. Required for
            token lifecycle endpoints; if absent they return 503.
    """
    from case_dashboard.auth import PortalSessionMiddleware

    global _SESSION_SECRET, _SESSION_MAX_AGE, _API_KEYS, _GATEWAY_CONFIG_PATH
    _SESSION_SECRET = session_secret
    _SESSION_MAX_AGE = session_max_age
    _API_KEYS = api_keys if api_keys is not None else {}
    _GATEWAY_CONFIG_PATH = Path(gateway_config_path) if gateway_config_path else None
    routes = _dashboard_api_routes()
    routes.append(Route("/{filename}", serve_v2_static, methods=["GET"]))
    routes.append(Route("/", serve_v2_index, methods=["GET"]))
    return Starlette(
        routes=routes,
        middleware=[
            Middleware(
                PortalSessionMiddleware,
                session_secret=session_secret,
                api_keys=_API_KEYS,
                session_max_age=session_max_age,
            ),
            Middleware(SecurityHeadersMiddleware),
        ],
    )
