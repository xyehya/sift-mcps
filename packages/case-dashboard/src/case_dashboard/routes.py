"""Case dashboard routes — Starlette sub-app for finding review."""

import getpass
import hashlib
import hmac as hmac_mod
import json
import logging
import os
import pwd
import re
import secrets
import shutil
import subprocess
import tempfile
import threading
import time
import uuid
from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import unquote

import yaml
from sift_core.approval_auth import (
    _load_password_entry as _load_pw_entry,
)
from sift_core.approval_auth import (
    _save_password_entry as _save_pw_entry,
)
from sift_core.approval_auth import (
    derive_auth_key,
    derive_ledger_key,
)
from sift_core.case_io import (
    _protected_write,
    case_approvals_path,
    case_audit_dir,
    cases_root,
    compute_content_hash,
)
from sift_core.evidence_chain import (
    init_evidence_chain,
)
from sift_core.verification import compute_hmac, write_ledger_entry
from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import FileResponse, JSONResponse, Response
from starlette.routing import Route

from case_dashboard.session_jwt import (
    COOKIE_NAME,
    COOKIE_PATH,
    COOKIE_SAME_SITE,
    SESSION_ENVELOPE_COOKIE_NAME,
    SESSION_ENVELOPE_COOKIE_PATH,
    SESSION_ENVELOPE_COOKIE_SAME_SITE,
    generate_jwt,
    generate_session_envelope,
    revoke_jti,
    verify_jwt,
    verify_session_envelope,
)

logger = logging.getLogger(__name__)

_STATIC_DIR = Path(__file__).parent / "static"
_PASSWORDS_DIR = Path("/var/lib/sift/passwords")

# Set by create_dashboard_v2_app() at startup from gateway.yaml config.
_SESSION_SECRET: str = ""
_SESSION_MAX_AGE: int = 28800
_API_KEYS: dict = {}

# Gateway config path and write lock — set by create_dashboard_v2_app().
# Needed for token lifecycle endpoints that must persist changes to gateway.yaml.
_GATEWAY_CONFIG_PATH: Path | None = None
_GATEWAY_CONFIG_LOCK = threading.Lock()
_TOKEN_REGISTRY = None

# PR03A — Gateway-injected Supabase auth callback boundary (C3 contract).
# This is an object exposing async login/resolve/refresh/issue_principal/
# revoke_principal/logout methods that return plain dicts (or None, or raise an
# exception carrying int .http_status and str .reason). case_dashboard NEVER
# imports sift_gateway; all Supabase/principal logic is reached through this.
_SUPABASE_AUTH = None
_ACTIVE_CASES = None

# BATCH-E1 — portal DB-authority seams. The Gateway injects these (same DI
# pattern as _ACTIVE_CASES / _SUPABASE_AUTH); case_dashboard NEVER imports
# sift_gateway. Each is an object exposing plain-dict-returning methods. When a
# slot is None the route falls back to the legacy file-backed path so existing
# suites and non-gateway deployments keep working. None of these ever surface
# absolute case/evidence/mount paths or secret material to the response.
#
#   _EVIDENCE_DB  -> DB evidence authority over the C1 custody RPCs
#                    (list_evidence / custody_events / seal / ignore / retire /
#                    verify_chain / gate_status). seal/ignore/retire/verify
#                    require a reauth_audit_event_id produced by the portal's
#                    existing password/HMAC re-auth.
#   _INVESTIGATION_DB -> DB authority for findings/timeline/todos/iocs read +
#                    todo mutations (list_findings / list_timeline / list_todos /
#                    list_iocs / create_todo / update_todo / delete_todo).
#                    Agent-authored rows are surfaced as proposed/draft until a
#                    human approves them through the portal.
#   _REPORT_DB    -> DB report metadata authority (list_reports / report_eligibility).
#                    Report GENERATION internals stay with BATCH-J1; E1 only wires
#                    metadata / eligibility / approval visibility.
#   _JOB_SERVICE  -> D2 Gateway job/status adapter (job_status_public).
_EVIDENCE_DB = None
_INVESTIGATION_DB = None
_REPORT_DB = None
_JOB_SERVICE = None
# When false, the legacy PBKDF2 challenge/login, sift_session HMAC cookie, and
# examiner Bearer fallback are disabled. Defaults to True so existing suites and
# non-Supabase deployments keep working; the Gateway passes the real flag.
_LEGACY_PORTAL_SESSION_ENABLED: bool = True


def _active_case_id() -> str | None:
    """Resolve the active case's opaque DB id (not a path) for DB-authority calls.

    Returns None when there is no DB active-case service or no active case. Never
    returns or logs an absolute path.
    """
    if _ACTIVE_CASES is None:
        return None
    try:
        case = _ACTIVE_CASES.get_active_case()
        cid = case.as_dict().get("case_id")
        return str(cid) if cid else None
    except Exception:
        return None


def _db_evidence_active() -> bool:
    """True when DB evidence authority is wired AND an active case is resolvable."""
    return _EVIDENCE_DB is not None and _active_case_id() is not None


def _db_investigation_active() -> bool:
    """True when DB investigation authority is wired AND an active case is resolvable."""
    return _INVESTIGATION_DB is not None and _active_case_id() is not None


def _reauth_event_id(request: Request) -> str | None:
    """Read the re-auth audit event id stamped on request.state by the re-auth path.

    The portal's password/HMAC re-auth helpers record an audit event id (when a DB
    audit sink is wired) and attach it to request.state.reauth_audit_event_id. The
    C1 seal/ignore/retire RPCs require this id; this is the single read point.
    """
    eid = getattr(request.state, "reauth_audit_event_id", None)
    return str(eid) if eid else None


def _legacy_password_auth_disabled() -> bool:
    """True when local PBKDF2 setup/challenge/reset endpoints must not run."""
    return _SUPABASE_AUTH is not None or not _LEGACY_PORTAL_SESSION_ENABLED


def _legacy_password_auth_disabled_response() -> JSONResponse:
    return JSONResponse({"error": "Legacy portal password auth disabled"}, status_code=403)

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
_CASE_ID_RE = re.compile(r"^[a-z][a-z0-9_-]{2,63}$")
_CASE_SLUG_INVALID_RE = re.compile(r"[^a-z0-9_-]+")
_CASE_SLUG_HYPHENS_RE = re.compile(r"-+")

# Evidence chain challenge store — domain-separated from commit challenges (R2)
_evidence_challenges: dict[str, dict] = {}
_EVIDENCE_CHALLENGE_TTL = 30  # seconds

# Case activation challenge store — domain-separated
_activation_challenges: dict[str, dict] = {}
_ACTIVATION_CHALLENGE_TTL = 30  # seconds

_MVP_REAUTH_METHOD = "local_hmac_mvp_bridge"
_MVP_REGISTRATION_MODE = "atomic_register_and_seal"

# Callback invoked after every successful evidence chain mutation (seal/ignore).
# Set by create_dashboard_v2_app() — the gateway passes invalidate_evidence_cache.
_ON_CHAIN_MUTATION: Callable[[str], None] | None = None

# Response-guard override callbacks — set by create_dashboard_v2_app().
# The gateway passes the three functions from sift_gateway.response_guard.
_OVERRIDE_GET_STATUS: Callable[[str], dict] | None = None
_OVERRIDE_ENABLE: Callable[[str, str, int], dict] | None = None
_OVERRIDE_CANCEL: Callable[[str], None] | None = None

_DEFAULT_OVERRIDE_TTL = 600  # 10 minutes

# Callback invoked after portal case creation activates a new case. Mounted
# Starlette sub-apps cannot reliably discover parent app.state, so the gateway
# injects its restart hook explicitly.
_ON_CASE_ACTIVATED: Callable[[str], object] | None = None


def _resolve_case_dir() -> Path | None:
    """Resolve the active case artifact directory for legacy file-backed reads."""
    if _ACTIVE_CASES is not None:
        try:
            case = _ACTIVE_CASES.get_active_case()
            artifact_path = case.as_dict().get("artifact_path")
            if artifact_path:
                p = Path(artifact_path)
                return p if p.is_dir() else None
        except Exception:
            return None

    # Legacy fallback for non-PR03B dashboard tests / CLI compatibility only.
    from sift_common import resolve_case_dir

    d = resolve_case_dir()
    if not d:
        return None
    p = Path(d)
    return p if p.is_dir() and (p / "CASE.yaml").exists() else None


def _active_case_dir_str() -> str:
    if _ACTIVE_CASES is None:
        return os.environ.get("SIFT_CASE_DIR", "")
    case_dir = _resolve_case_dir()
    return str(case_dir) if case_dir is not None else ""


def _no_case_response() -> JSONResponse:
    return JSONResponse(
        {"error": "No active case selected in Postgres active_case_state."},
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
    approvals = _load_jsonl(case_approvals_path(case_dir))

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


def _require_portal_role(request: Request) -> JSONResponse | None:
    """Return 403 unless the authenticated portal principal has a valid role (examiner or readonly)."""
    role = getattr(request.state, "role", None)
    if role not in ("examiner", "readonly"):
        return JSONResponse(
            {"error": "Examiner or Readonly role required"},
            status_code=403,
        )
    return None


def _active_case_error_response(exc: Exception, default: int = 500) -> JSONResponse:
    status = getattr(exc, "http_status", None)
    if not isinstance(status, int) or status < 400 or status > 599:
        status = default
    reason = getattr(exc, "reason", None) or str(exc) or "active_case_error"
    return JSONResponse({"error": reason}, status_code=status)


def _configured_runtime_user() -> str:
    """Return the low-privilege run_command user, or empty for same-user mode."""
    raw = os.environ.get("SIFT_EXECUTE_AS_USER")
    if raw is None and _GATEWAY_CONFIG_PATH is not None:
        try:
            config = yaml.safe_load(_GATEWAY_CONFIG_PATH.read_text()) or {}
            execute = config.get("execute", {}) if isinstance(config, dict) else {}
            if isinstance(execute, dict):
                raw = execute.get("runtime_user")
        except Exception as exc:
            logger.warning("runtime ACL: could not read gateway config: %s", exc)
    runtime_user = str(raw if raw is not None else "agent_runtime").strip()
    if runtime_user == "__current__":
        return ""
    return runtime_user


def _configure_agent_runtime_case_acl(case_dir: Path) -> dict:
    """Grant the native run_command user access to a newly created case tree.

    ``scripts/setup-agent-runtime.sh`` configures the host user/sudo baseline.
    This per-case hook covers newly created directories so allowed
    ``run_command`` executions can read sealed evidence and write only to
    agent-owned output areas. ACL failures are logged but do not fail case
    creation; the execution path still fails closed if the runtime user cannot
    read/write the target at call time.
    """
    runtime_user = _configured_runtime_user()
    if not runtime_user:
        return {"status": "skipped", "reason": "same_user"}
    try:
        pwd.getpwnam(runtime_user)
    except KeyError:
        return {"status": "skipped", "reason": "runtime_user_missing", "user": runtime_user}
    setfacl = shutil.which("setfacl")
    if not setfacl:
        return {"status": "skipped", "reason": "setfacl_missing", "user": runtime_user}

    writable_dirs = [
        case_dir / "agent",
        case_dir / "agent" / "outputs",
        case_dir / "agent" / "run_commands",
        case_dir / "extractions",
        case_dir / "tmp",
    ]
    for path in writable_dirs:
        path.mkdir(parents=True, exist_ok=True)

    commands: list[list[str]] = [
        [setfacl, "-m", f"u:{runtime_user}:r-x", str(case_dir)],
    ]
    for path in writable_dirs:
        commands.append([setfacl, "-m", f"u:{runtime_user}:rwx", str(path)])
        commands.append([setfacl, "-d", "-m", f"u:{runtime_user}:rwx", str(path)])

    evidence_dir = case_dir / "evidence"
    if evidence_dir.is_dir():
        commands.append([setfacl, "-m", f"u:{runtime_user}:r-x", str(evidence_dir)])
        commands.append([setfacl, "-d", "-m", f"u:{runtime_user}:r-x", str(evidence_dir)])

    protected_paths = [
        case_dir / "audit",
        case_dir / "approvals.jsonl",
        case_dir / "evidence-ledger.jsonl",
        case_dir / "evidence-manifest.json",
        case_dir / "evidence-verify-state.json",
    ]
    for path in protected_paths:
        if not path.exists():
            continue
        commands.append([setfacl, "-m", f"u:{runtime_user}:---", str(path)])
        if path.is_dir():
            commands.append([setfacl, "-d", "-m", f"u:{runtime_user}:---", str(path)])

    failures = []
    for cmd in commands:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=False,
        )
        if result.returncode != 0:
            failures.append({"cmd": cmd[:3], "stderr": (result.stderr or "").strip()})
    if failures:
        logger.warning("runtime ACL: %d setfacl command(s) failed", len(failures))
        return {"status": "partial", "user": runtime_user, "failures": failures}
    return {"status": "configured", "user": runtime_user}


def _request_principal(request: Request) -> dict | None:
    principal = getattr(request.state, "principal", None)
    return principal if isinstance(principal, dict) else None


def _check_commit_lockout(examiner: str) -> str | None:
    """Returns error message if locked out, None if OK."""
    lockout_file = Path.home() / ".sift" / ".password_lockout"
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
    lockout_file = Path.home() / ".sift" / ".password_lockout"
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
    lockout_file = Path.home() / ".sift" / ".password_lockout"
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
    lockout_file = Path.home() / ".sift" / ".password_lockout"
    try:
        data = json.loads(lockout_file.read_text())
    except (OSError, json.JSONDecodeError):
        return 0
    now = time.time()
    return sum(1 for t in data.get(examiner, []) if now - t < _COMMIT_LOCKOUT_SECONDS)


# Login lockout helpers — use "login:{examiner}" as the key (R2: separate namespace)

def _check_login_lockout(examiner: str) -> str | None:
    """Returns error message if login is locked out; None if OK. R2: login: namespace."""
    lockout_file = Path.home() / ".sift" / ".password_lockout"
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


# ---------------------------------------------------------------------------
# Evidence chain helpers (Phase 16a)
# ---------------------------------------------------------------------------

_WRITE_BLOCK_WARNING = (
    "Evidence directory is not write-protected. "
    "Forensic best practice requires mounting acquired evidence read-only "
    "via hardware write-blocker or 'mount -o ro,noatime'."
)


def _detect_write_block(evidence_dir: Path) -> dict:
    """Detect whether evidence/ is on a read-only mount.

    Returns {write_protected: bool, mount_point?: str, warning?: str}.
    mtime is not used for integrity — this is for display purposes only.
    """
    if not evidence_dir.exists():
        return {"write_protected": False, "warning": "Evidence directory does not exist"}

    resolved = str(evidence_dir.resolve())

    # Primary: /proc/mounts (Linux)
    try:
        mounts_text = Path("/proc/mounts").read_text()
        best_mp: str | None = None
        best_opts: list[str] = []
        for line in mounts_text.splitlines():
            parts = line.split()
            if len(parts) < 4:
                continue
            mp = parts[1]
            if (resolved == mp or resolved.startswith(mp + "/")) and len(mp) > len(best_mp or ""):
                best_mp = mp
                best_opts = parts[3].split(",")
        if best_mp:
            if "ro" in best_opts:
                return {"write_protected": True, "mount_point": best_mp}
            return {"write_protected": False, "mount_point": best_mp, "warning": _WRITE_BLOCK_WARNING}
    except OSError:
        pass

    # Fallback: statvfs ST_RDONLY flag (0x0001)
    try:
        vfs = os.statvfs(str(evidence_dir))
        if vfs.f_flag & 0x0001:
            return {"write_protected": True}
    except (OSError, AttributeError):
        pass

    return {"write_protected": False, "warning": _WRITE_BLOCK_WARNING}


def _verify_evidence_hmac(
    examiner: str,
    challenge_id: str,
    response_hmac: str,
    client_ip: str,
) -> tuple[str | None, bytes | None]:
    """Verify an evidence chain HMAC challenge. Returns (error_msg | None, derived_key | None)."""
    now = time.time()
    challenge = _evidence_challenges.pop(challenge_id, None)
    if not challenge:
        return "Invalid or expired challenge", None
    if now - challenge["created_at"] > _EVIDENCE_CHALLENGE_TTL:
        return "Challenge expired", None
    if challenge.get("bound_ip") != client_ip:
        return "Challenge IP mismatch", None
    if challenge["examiner"] != examiner:
        return "Challenge/examiner mismatch", None

    entry = _load_pw_entry(_PASSWORDS_DIR, examiner)
    if not entry:
        return "No password configured", None
    try:
        stored_hash = bytes.fromhex(entry["hash"])
    except (ValueError, KeyError):
        return "Password data corrupted", None

    expected = hmac_mod.new(stored_hash, challenge["nonce"].encode(), "sha256").hexdigest()
    if not hmac_mod.compare_digest(expected, response_hmac):
        _record_commit_failure(f"evidence:{examiner}")
        return "Incorrect password", None

    _clear_commit_failures(f"evidence:{examiner}")
    return None, derive_ledger_key(entry["hash"])


def _record_reauth_event(request: Request, examiner: str, action: str) -> str | None:
    """Record a successful re-auth as an audit event and return its id.

    Used by the C1 seal/ignore/retire RPCs which reject a transition without a
    reauth_audit_event_id. The DB evidence service owns the audit_events write;
    when no DB service is wired (file-backed/tests) this returns None and the
    file-backed path is used instead. The id is stamped on request.state so a
    single re-auth covers the whole handler.
    """
    if _EVIDENCE_DB is None:
        return None
    recorder = getattr(_EVIDENCE_DB, "record_reauth_event", None)
    if not callable(recorder):
        return None
    try:
        eid = recorder(
            case_id=_active_case_id(),
            actor=_request_principal(request),
            examiner=examiner,
            action=action,
        )
    except Exception as exc:
        logger.warning("re-auth audit event record failed: %s", exc)
        return None
    if eid:
        request.state.reauth_audit_event_id = str(eid)
    return str(eid) if eid else None


# ---------------------------------------------------------------------------
# Evidence chain endpoint handlers (Phase 16a)
# ---------------------------------------------------------------------------


def _empty_evidence_chain_status() -> dict:
    """Graceful no-case/empty evidence chain payload (DB-authority shape).

    Returned on a fresh install (no DB evidence service wired or no active case)
    so the evidence APIs degrade to an empty payload with HTTP 200 instead of a
    404/500. Carries every key the frontend contract expects, all empty/neutral.
    """
    keypair_configured = bool(os.environ.get("SIFT_SOLANA_KEYPAIR", "").strip())
    return {
        "authority": "db",
        "status": "no_case",
        "seal_status": "no_case",
        "manifest_version": 0,
        "active_count": 0,
        "issues": [],
        "head_hash": "",
        "hmac_last_verified_at": None,
        "hmac_last_verified_by": None,
        "hmac_verify_needed": False,
        "anchor": {"anchoring_enabled": keypair_configured, "manifest_version": 0},
        "unregistered": [],
        "missing": [],
        "modified": [],
        "ok": [],
        "write_protected": False,
        "write_block_mount_point": None,
        "write_block_warning": None,
        "requires_examiner_action": False,
    }


def _db_evidence_chain_status() -> dict | None:
    """Assemble the evidence chain status payload from DB custody authority (C1).

    The single evidence-chain-status builder. DB authority is the only authority:
    ``app.evidence_gate_status`` + ``app.evidence_objects``. Returns None when no
    DB evidence service is wired or no active case; the caller (``_evidence_chain_status``)
    degrades that to a graceful empty payload. Only relative display paths and
    seal/custody summary fields are surfaced — never absolute mount paths.
    """
    if _EVIDENCE_DB is None:
        return None
    case_id = _active_case_id()
    if not case_id:
        return None
    gate = getattr(_EVIDENCE_DB, "gate_status", None)
    if not callable(gate):
        return None
    try:
        status = gate(case_id) or {}
    except Exception as exc:
        logger.warning("DB evidence gate_status failed: %s", exc)
        return None

    seal_status = status.get("seal_status", "unsealed")
    payload = {
        "authority": "db",
        "status": seal_status,
        "seal_status": seal_status,
        "manifest_version": status.get("manifest_version", 0),
        "active_count": status.get("active_count", 0),
        "issues": status.get("issues", []),
        "head_hash": status.get("head_hash", ""),
        "hmac_last_verified_at": status.get("last_verified_at"),
        # The DB gate does not (yet) record the verifying examiner; surface it when
        # the gate/reauth metadata carries it, else None.
        "hmac_last_verified_by": status.get("last_verified_by"),
        "hmac_verify_needed": status.get("last_verified_at") is None,
    }

    # Detected-vs-sealed object lists for the frontend (Seal Manifest specs,
    # custody badges). Derived from DB custody authority — list_evidence() rescans
    # the mounted tree → DB first, so these reflect current disk state.
    unregistered: list[str] = []
    missing: list[str] = []
    modified: list[str] = []
    ok: list[str] = []
    lister = getattr(_EVIDENCE_DB, "list_evidence", None)
    if callable(lister):
        try:
            items = lister(case_id) or []
        except Exception as exc:
            logger.warning("DB list_evidence for chain status failed: %s", exc)
            items = []
        for item in items:
            if not isinstance(item, dict):
                continue
            dp = item.get("display_path") or ""
            if not dp:
                continue
            obj_status = item.get("status")
            obj_seal = item.get("seal_status")
            # Operator-dispositioned objects are not actionable and must not appear
            # in the actionable Seal-Manifest set, even though their seal_status is
            # still "unsealed".
            if obj_status in ("ignored", "retired"):
                continue
            if obj_seal == "missing":
                missing.append(dp)
            elif obj_seal in ("modified", "violated"):
                modified.append(dp)
            elif obj_status == "sealed" or obj_seal == "sealed":
                ok.append(dp)
            elif obj_status == "detected":
                unregistered.append(dp)
    # Fall back to the gate's own unregistered list when list_evidence is unavailable.
    if not unregistered and isinstance(status.get("unregistered"), list):
        unregistered = [str(p) for p in status["unregistered"]]
    payload["unregistered"] = unregistered
    payload["missing"] = missing
    payload["modified"] = modified
    payload["ok"] = ok

    # Write-block detection is a filesystem mount read-only check (display only),
    # not file-state authority. Resolve the evidence dir from the active case
    # artifact path when obtainable; _detect_write_block returns a mount-point
    # label only, never the absolute evidence path.
    write_protected = False
    write_block_mount_point = None
    write_block_warning = None
    case_dir = _resolve_case_dir()
    if case_dir is not None:
        wb = _detect_write_block(case_dir / "evidence")
        write_protected = wb.get("write_protected", False)
        write_block_mount_point = wb.get("mount_point")
        write_block_warning = wb.get("warning")
    payload["write_protected"] = write_protected
    payload["write_block_mount_point"] = write_block_mount_point
    payload["write_block_warning"] = write_block_warning

    payload["requires_examiner_action"] = (seal_status != "sealed") or bool(unregistered)

    # Surface the latest DB-recorded proof export + Solana anchor metadata so the
    # portal anchor/proof badge works in DB-active mode. Anchor metadata is
    # external proof only; absence is reported as not-configured, never an error.
    keypair_configured = bool(os.environ.get("SIFT_SOLANA_KEYPAIR", "").strip())
    anchor_info: dict = {
        "anchoring_enabled": keypair_configured,
        "manifest_version": payload["manifest_version"],
    }
    latest = getattr(_EVIDENCE_DB, "latest_proof_export", None)
    if callable(latest):
        try:
            export = latest(case_id)
        except Exception as exc:
            logger.warning("DB latest_proof_export failed: %s", exc)
            export = None
        if export is not None:
            payload["proof_export"] = export
            anchor = export.get("anchor") or {}
            if anchor:
                anchor_info.update({
                    "solana_tx": anchor.get("solana_tx"),
                    "confirmed": anchor.get("confirmed", False),
                    "cluster": anchor.get("cluster") or "mainnet",
                    "explorer_url": anchor.get("explorer_url"),
                    "timestamp": export.get("verified_at"),
                })
    payload["anchor"] = anchor_info
    return payload


def _evidence_chain_status() -> dict:
    """Return the DB-authority evidence chain status, or a graceful empty payload.

    Never returns None and never raises: a fresh install with no DB evidence
    service or no active case degrades to ``_empty_evidence_chain_status`` (HTTP
    200 / no_case), so the evidence cycle never 500s or blocks.
    """
    try:
        db = _db_evidence_chain_status()
    except Exception as exc:
        logger.warning("evidence chain status failed: %s", exc)
        db = None
    return db if db is not None else _empty_evidence_chain_status()


def _db_export_proof_after_seal(request, examiner):
    """Generate the DB-derived proof export after a DB-active seal.

    Returns (anchor_info | None, proof_info | None). Optional Solana anchoring is
    attempted only when SIFT_SOLANA_KEYPAIR is configured; the anchor result is
    folded into the proof export metadata in Postgres. Anchoring never blocks the
    seal — any failure degrades to a recorded proof export without an on-chain tx.
    """
    exporter = getattr(_EVIDENCE_DB, "export_proof", None)
    if not callable(exporter):
        return None, None
    case_id = _active_case_id()
    if not case_id:
        return None, None

    anchor_proof: dict | None = None
    anchor_info: dict | None = None
    keypair_path = os.environ.get("SIFT_SOLANA_KEYPAIR", "").strip() or None
    if keypair_path:
        gate = getattr(_EVIDENCE_DB, "gate_status", None)
        head = gate(case_id) if callable(gate) else {}
        head = head if isinstance(head, dict) else {}
        try:
            from sift_core.evidence_chain import anchor_db_proof
            anchor_proof = anchor_db_proof(
                manifest_version=head.get("manifest_version", 0),
                manifest_hash=head.get("head_hash", "") or "",
                ledger_tip_hash=head.get("head_hash", "") or "",
                keypair_path=keypair_path,
                cluster=os.environ.get("SIFT_SOLANA_CLUSTER", "mainnet"),
            )
            anchor_info = {
                "solana_tx": anchor_proof.get("solana_tx"),
                "confirmed": anchor_proof.get("confirmed"),
                "explorer_url": anchor_proof.get("explorer_url"),
            }
        except Exception as exc:
            logger.warning("evidence seal: DB Solana anchor failed: %s", exc)
            anchor_proof = None

    try:
        proof_info = exporter(
            case_id=case_id,
            actor=_request_principal(request),
            export_kind="bundle",
            anchor=anchor_proof,
        )
    except Exception as exc:
        logger.warning("evidence seal: DB proof export failed: %s", exc)
        return anchor_info, None
    return anchor_info, proof_info


async def get_evidence_chain_status(request: Request) -> JSONResponse:
    """Return evidence chain status, diff, and write-block detection. No mutation.

    DB custody authority only (C1). On a fresh install (no DB evidence service or
    no active case) this degrades to a graceful empty/no_case payload with HTTP
    200 — it never 404s or 500s.
    """
    role_err = _require_portal_role(request)
    if role_err:
        return role_err

    return JSONResponse(_evidence_chain_status())


async def post_evidence_chain_rescan(request: Request) -> JSONResponse:
    """Drop the evidence gate cache and return a fresh DB-authority status."""
    role_err = _require_examiner_role(request)
    if role_err:
        return role_err

    case_dir_str = _active_case_dir_str()
    if _ON_CHAIN_MUTATION and case_dir_str:
        try:
            _ON_CHAIN_MUTATION(case_dir_str)
        except Exception as exc:
            logger.warning("evidence rescan: cache invalidation failed: %s", exc)

    return JSONResponse(_evidence_chain_status())


async def get_evidence_chain_challenge(request: Request) -> JSONResponse:
    """Issue a challenge nonce for evidence seal/ignore operations."""
    role_err = _require_examiner_role(request)
    if role_err:
        return role_err

    examiner = _resolve_examiner(request)
    if not examiner:
        return JSONResponse({"error": "No examiner identity"}, status_code=401)

    err = _must_reset_check(examiner)
    if err:
        return err

    lockout_msg = _check_commit_lockout(f"evidence:{examiner}")
    if lockout_msg:
        return JSONResponse({"error": lockout_msg}, status_code=429)

    entry = _load_pw_entry(_PASSWORDS_DIR, examiner)
    if not entry:
        return JSONResponse({"error": "No password configured"}, status_code=403)

    # Purge expired evidence challenges
    now = time.time()
    expired = [k for k, v in _evidence_challenges.items() if now - v["created_at"] > _EVIDENCE_CHALLENGE_TTL]
    for k in expired:
        del _evidence_challenges[k]

    challenge_id = secrets.token_hex(16)
    nonce = secrets.token_hex(32)
    _evidence_challenges[challenge_id] = {
        "nonce": nonce,
        "examiner": examiner,
        "created_at": now,
        "bound_ip": request.client.host,
    }

    return JSONResponse({
        "challenge_id": challenge_id,
        "nonce": nonce,
        "salt": entry["salt"],
        "iterations": 600000,
        "hash_algorithm": "SHA-256",
        "reauth_method": _MVP_REAUTH_METHOD,
    })


async def post_evidence_chain_seal(request: Request) -> JSONResponse:
    """Seal a new evidence manifest version with HMAC confirmation.

    Body: {challenge_id, response, file_specs: [{path, source?, description?}]}
    Requires: session examiner + role examiner + must_reset_password=false + HMAC.
    """
    role_err = _require_examiner_role(request)
    if role_err:
        return role_err

    examiner = _resolve_examiner(request)
    if not examiner:
        return JSONResponse({"error": "No examiner identity"}, status_code=401)

    err = _must_reset_check(examiner)
    if err:
        return err

    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"error": "Invalid JSON"}, status_code=400)

    challenge_id = str(body.get("challenge_id", ""))
    response_hmac = str(body.get("response", ""))
    file_specs = body.get("file_specs", [])

    if not challenge_id or not response_hmac:
        return JSONResponse({"error": "Missing challenge_id or response"}, status_code=400)
    if not isinstance(file_specs, list):
        return JSONResponse({"error": "file_specs must be a list"}, status_code=400)

    err_msg, _derived_key = _verify_evidence_hmac(
        examiner, challenge_id, response_hmac, request.client.host
    )
    if err_msg:
        return JSONResponse({"error": err_msg}, status_code=401)

    # Validate file_specs entries
    for spec in file_specs:
        if not isinstance(spec, dict) or "path" not in spec:
            return JSONResponse({"error": "Each file_spec must have a 'path' key"}, status_code=400)

    # DB custody authority only (C1): the seal RPC requires a reauth audit event
    # id. The broker resolves the relative display paths to mounted bytes and
    # computes the hashes; the portal never sends absolute paths. Without DB
    # authority there is no file-backed fallback — degrade gracefully to no_case.
    sealer = getattr(_EVIDENCE_DB, "seal", None) if _EVIDENCE_DB is not None else None
    if not callable(sealer):
        return _no_case_response()

    reauth_id = _record_reauth_event(request, examiner, "evidence_seal")
    if not reauth_id:
        return JSONResponse(
            {"error": "Re-auth audit event required for seal"},
            status_code=403,
        )
    try:
        head = sealer(
            case_id=_active_case_id(),
            file_specs=file_specs,
            reauth_audit_event_id=reauth_id,
            actor=_request_principal(request),
            examiner=examiner,
        )
    except Exception as exc:
        return _active_case_error_response(exc, default=500)
    head = head if isinstance(head, dict) else {}

    case_dir_str = _active_case_dir_str()
    if _ON_CHAIN_MUTATION and case_dir_str:
        try:
            _ON_CHAIN_MUTATION(case_dir_str)
        except Exception as exc:
            logger.warning("evidence seal: cache invalidation failed: %s", exc)

    # DB-first proof export: derive proof material from DB custody state and record
    # metadata/hash in Postgres. Optional Solana anchoring is external proof only
    # and must never block the seal.
    anchor_info, proof_info = _db_export_proof_after_seal(request, examiner)
    resp = {
        "sealed": True,
        "authority": "db",
        "registration_mode": _MVP_REGISTRATION_MODE,
        "reauth_method": _MVP_REAUTH_METHOD,
        "manifest_version": head.get("manifest_version"),
        "seal_status": head.get("seal_status", "sealed"),
        "files_added": [s.get("path") for s in file_specs],
    }
    if proof_info is not None:
        resp["proof_export"] = proof_info
    if anchor_info is not None:
        resp["anchor"] = anchor_info
    return JSONResponse(resp)


async def post_evidence_chain_ignore(request: Request) -> JSONResponse:
    """Mark an unregistered evidence file as intentionally ignored with HMAC confirmation.

    Body: {challenge_id, response, path, reason}
    Requires: session examiner + role examiner + must_reset_password=false + HMAC.
    """
    role_err = _require_examiner_role(request)
    if role_err:
        return role_err

    examiner = _resolve_examiner(request)
    if not examiner:
        return JSONResponse({"error": "No examiner identity"}, status_code=401)

    err = _must_reset_check(examiner)
    if err:
        return err

    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"error": "Invalid JSON"}, status_code=400)

    challenge_id = str(body.get("challenge_id", ""))
    response_hmac = str(body.get("response", ""))
    rel_path = str(body.get("path", "")).strip()
    reason = str(body.get("reason", "")).strip()

    if not challenge_id or not response_hmac:
        return JSONResponse({"error": "Missing challenge_id or response"}, status_code=400)
    if not rel_path:
        return JSONResponse({"error": "Missing path"}, status_code=400)
    if not reason:
        return JSONResponse({"error": "Missing reason"}, status_code=400)

    err_msg, _derived_key = _verify_evidence_hmac(
        examiner, challenge_id, response_hmac, request.client.host
    )
    if err_msg:
        return JSONResponse({"error": err_msg}, status_code=401)

    # DB custody authority only (C1). No file-backed fallback; degrade gracefully.
    ignorer = getattr(_EVIDENCE_DB, "ignore", None) if _EVIDENCE_DB is not None else None
    if not callable(ignorer):
        return _no_case_response()

    reauth_id = _record_reauth_event(request, examiner, "evidence_ignore")
    if not reauth_id:
        return JSONResponse(
            {"error": "Re-auth audit event required for ignore"},
            status_code=403,
        )
    try:
        ignorer(
            case_id=_active_case_id(),
            display_path=rel_path,
            reason=reason,
            reauth_audit_event_id=reauth_id,
            actor=_request_principal(request),
            examiner=examiner,
        )
    except Exception as exc:
        return _active_case_error_response(exc, default=500)

    case_dir_str = _active_case_dir_str()
    if _ON_CHAIN_MUTATION and case_dir_str:
        try:
            _ON_CHAIN_MUTATION(case_dir_str)
        except Exception as exc:
            logger.warning("evidence ignore: cache invalidation failed: %s", exc)

    return JSONResponse({
        "ignored": True,
        "authority": "db",
        "path": rel_path,
        "reauth_method": _MVP_REAUTH_METHOD,
    })


async def post_evidence_chain_delete(request: Request) -> JSONResponse:
    """Physically delete a non-sealed stray evidence file with HMAC confirmation.

    Body: {challenge_id, response, path, reason}
    Requires: session examiner + role examiner + must_reset_password=false + HMAC.

    Unlike ignore (which only marks the DB object dispositioned, leaving the bytes
    on disk and still readable by the AI agent via run_command), delete removes the
    file bytes so a planted/stray/hidden file can no longer be parsed or indexed by
    the agent. Sealed evidence cannot be deleted (custody integrity). The removed
    file's sha256 + size are recorded in an append-only custody event.
    """
    role_err = _require_examiner_role(request)
    if role_err:
        return role_err

    examiner = _resolve_examiner(request)
    if not examiner:
        return JSONResponse({"error": "No examiner identity"}, status_code=401)

    err = _must_reset_check(examiner)
    if err:
        return err

    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"error": "Invalid JSON"}, status_code=400)

    challenge_id = str(body.get("challenge_id", ""))
    response_hmac = str(body.get("response", ""))
    rel_path = str(body.get("path", "")).strip()
    reason = str(body.get("reason", "")).strip()

    if not challenge_id or not response_hmac:
        return JSONResponse({"error": "Missing challenge_id or response"}, status_code=400)
    if not rel_path:
        return JSONResponse({"error": "Missing path"}, status_code=400)
    if not reason:
        return JSONResponse({"error": "Missing reason"}, status_code=400)

    err_msg, _derived_key = _verify_evidence_hmac(
        examiner, challenge_id, response_hmac, request.client.host
    )
    if err_msg:
        return JSONResponse({"error": err_msg}, status_code=401)

    # DB custody authority only. No file-backed fallback; degrade gracefully.
    deleter = getattr(_EVIDENCE_DB, "delete_object", None) if _EVIDENCE_DB is not None else None
    if not callable(deleter):
        return _no_case_response()

    reauth_id = _record_reauth_event(request, examiner, "evidence_delete")
    if not reauth_id:
        return JSONResponse(
            {"error": "Re-auth audit event required for delete"},
            status_code=403,
        )
    try:
        result = deleter(
            case_id=_active_case_id(),
            display_path=rel_path,
            reason=reason,
            reauth_audit_event_id=reauth_id,
            actor=_request_principal(request),
            examiner=examiner,
        )
    except Exception as exc:
        return _active_case_error_response(exc, default=500)
    result = result if isinstance(result, dict) else {}

    case_dir_str = _active_case_dir_str()
    if _ON_CHAIN_MUTATION and case_dir_str:
        try:
            _ON_CHAIN_MUTATION(case_dir_str)
        except Exception as exc:
            logger.warning("evidence delete: cache invalidation failed: %s", exc)

    return JSONResponse({
        "deleted": True,
        "authority": "db",
        "path": rel_path,
        "file_removed": result.get("file_removed", False),
        "sha256": result.get("sha256"),
        "bytes": result.get("bytes"),
        "reauth_method": _MVP_REAUTH_METHOD,
    })


async def post_evidence_chain_retire(request: Request) -> JSONResponse:
    """Retire a registered evidence file with HMAC confirmation.

    Documents the deliberate removal of an ACTIVE evidence file.
    Distinct from ignore (which is for unregistered files).
    Clears the immutable flag and deletes the file from disk after
    recording the FILE_RETIRED ledger event.

    Body: {challenge_id, response, path, reason}
    Requires: session examiner + role examiner + must_reset_password=false + HMAC.
    """
    role_err = _require_examiner_role(request)
    if role_err:
        return role_err

    examiner = _resolve_examiner(request)
    if not examiner:
        return JSONResponse({"error": "No examiner identity"}, status_code=401)

    err = _must_reset_check(examiner)
    if err:
        return err

    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"error": "Invalid JSON"}, status_code=400)

    challenge_id = str(body.get("challenge_id", ""))
    response_hmac = str(body.get("response", ""))
    rel_path = str(body.get("path", "")).strip()
    reason = str(body.get("reason", "")).strip()

    if not challenge_id or not response_hmac:
        return JSONResponse({"error": "Missing challenge_id or response"}, status_code=400)
    if not rel_path:
        return JSONResponse({"error": "Missing path"}, status_code=400)
    if not reason:
        return JSONResponse({"error": "Missing reason"}, status_code=400)

    err_msg, _derived_key = _verify_evidence_hmac(
        examiner, challenge_id, response_hmac, request.client.host
    )
    if err_msg:
        return JSONResponse({"error": err_msg}, status_code=401)

    # DB custody authority only (C1). No file-backed fallback; degrade gracefully.
    retirer = getattr(_EVIDENCE_DB, "retire", None) if _EVIDENCE_DB is not None else None
    if not callable(retirer):
        return _no_case_response()

    reauth_id = _record_reauth_event(request, examiner, "evidence_retire")
    if not reauth_id:
        return JSONResponse(
            {"error": "Re-auth audit event required for retire"},
            status_code=403,
        )
    try:
        retirer(
            case_id=_active_case_id(),
            display_path=rel_path,
            reason=reason,
            reauth_audit_event_id=reauth_id,
            actor=_request_principal(request),
            examiner=examiner,
        )
    except Exception as exc:
        return _active_case_error_response(exc, default=500)

    case_dir_str = _active_case_dir_str()
    if _ON_CHAIN_MUTATION and case_dir_str:
        try:
            _ON_CHAIN_MUTATION(case_dir_str)
        except Exception as exc:
            logger.warning("evidence retire: cache invalidation failed: %s", exc)

    return JSONResponse({
        "retired": True,
        "authority": "db",
        "path": rel_path,
        "reauth_method": _MVP_REAUTH_METHOD,
    })


# ---------------------------------------------------------------------------
# Evidence chain HMAC verify endpoint (Phase 16-verify-remind)
# ---------------------------------------------------------------------------


async def post_evidence_chain_verify_hmac(request: Request) -> JSONResponse:
    """Re-verify sealed evidence against DB custody authority with HMAC confirmation.

    DB custody authority only (C1): ``_EVIDENCE_DB.verify`` re-hashes the sealed
    objects and records the outcome (escalating to ``violated`` on failure); the
    verify timestamp is surfaced via the DB gate's ``last_verified_at`` so the
    portal can remind the examiner. No ledger/manifest file is read. Without DB
    authority there is no file-backed fallback — degrade gracefully to no_case.

    Body: {challenge_id, response}
    Requires: session examiner + role examiner + must_reset_password=false + HMAC.
    Returns: {ok, verified, issues, verified_at, verified_by, authority}
    """
    role_err = _require_examiner_role(request)
    if role_err:
        return role_err

    examiner = _resolve_examiner(request)
    if not examiner:
        return JSONResponse({"error": "No examiner identity"}, status_code=401)

    err = _must_reset_check(examiner)
    if err:
        return err

    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"error": "Invalid JSON"}, status_code=400)

    challenge_id = str(body.get("challenge_id", ""))
    response_hmac = str(body.get("response", ""))

    if not challenge_id or not response_hmac:
        return JSONResponse({"error": "Missing challenge_id or response"}, status_code=400)

    err_msg, _derived_key = _verify_evidence_hmac(
        examiner, challenge_id, response_hmac, request.client.host
    )
    if err_msg:
        return JSONResponse({"error": err_msg}, status_code=401)

    verifier = getattr(_EVIDENCE_DB, "verify", None) if _EVIDENCE_DB is not None else None
    if not callable(verifier):
        return _no_case_response()

    try:
        result = verifier(case_id=_active_case_id(), actor=_request_principal(request))
    except Exception as exc:
        logger.warning("DB evidence verify failed: %s", type(exc).__name__)
        return JSONResponse(
            {"error": "HMAC verify failed — check gateway logs"}, status_code=500
        )
    result = result if isinstance(result, dict) else {}
    verified = bool(result.get("verified"))

    from datetime import datetime, timezone
    verified_at = datetime.now(timezone.utc).isoformat()

    return JSONResponse({
        "ok": verified,
        "verified": verified,
        "issues": result.get("issues", []),
        "verified_at": verified_at,
        "verified_by": examiner,
        "authority": "db",
    })


# ---------------------------------------------------------------------------
# Solana anchor endpoint (Phase 16e — manual re-anchor)
# ---------------------------------------------------------------------------


async def post_evidence_chain_anchor(request: Request) -> JSONResponse:
    """Anchor current manifest on Solana. Session auth, no HMAC required.

    Writes evidence-anchor-v{N}.json and returns anchor status.
    Returns 503 if SIFT_SOLANA_KEYPAIR is not configured.
    """
    role_err = _require_examiner_role(request)
    if role_err:
        return role_err

    keypair_path = os.environ.get("SIFT_SOLANA_KEYPAIR", "").strip() or None
    if not keypair_path:
        return JSONResponse(
            {"error": "Solana anchoring not configured — set SIFT_SOLANA_KEYPAIR"},
            status_code=503,
        )

    # DB-authority path: anchor DB-derived proof material and record it in
    # app.evidence_proof_exports. No case file is read or written as authority.
    # DB custody authority only; without it there is no file-backed fallback.
    if not _db_evidence_active():
        return _no_case_response()

    anchor_info, proof_info = _db_export_proof_after_seal(request, _resolve_examiner(request))
    anchor_info = anchor_info or {}
    return JSONResponse({
        "authority": "db",
        "anchored": anchor_info.get("solana_tx") is not None,
        "manifest_version": (proof_info or {}).get("manifest_version"),
        "solana_tx": anchor_info.get("solana_tx"),
        "confirmed": anchor_info.get("confirmed"),
        "explorer_url": anchor_info.get("explorer_url"),
        "proof_export": proof_info,
    })


async def post_evidence_chain_proof_export(request: Request) -> JSONResponse:
    """Generate a DB-derived proof export and record its metadata in Postgres.

    DB-active only. The proof bundle (sealed object snapshot, custody event
    chain, chain head) is derived from DB custody authority; mounted evidence is
    re-verified by full re-hash and the verify outcome + content hash are
    recorded via app.evidence_record_proof_export. Optional Solana anchoring is
    attempted when configured and recorded as external proof; its absence does
    not fail the export.
    """
    role_err = _require_examiner_role(request)
    if role_err:
        return role_err

    if not _db_evidence_active():
        return JSONResponse(
            {"error": "Proof export requires DB evidence authority"},
            status_code=503,
        )

    examiner = _resolve_examiner(request)
    anchor_info, proof_info = _db_export_proof_after_seal(request, examiner)
    if proof_info is None:
        return JSONResponse(
            {"error": "Proof export failed — check gateway logs"},
            status_code=500,
        )
    resp = {"authority": "db", "proof_export": proof_info}
    if anchor_info is not None:
        resp["anchor"] = anchor_info
    return JSONResponse(resp)


# ---------------------------------------------------------------------------
# Response-guard override endpoints (Approach C / Phase 16a-guard)
# ---------------------------------------------------------------------------


async def get_response_guard_status(request: Request) -> JSONResponse:
    """Return current response-guard override status. Session auth, no HMAC."""
    role_err = _require_portal_role(request)
    if role_err:
        return role_err

    case_dir_str = _active_case_dir_str()
    if _OVERRIDE_GET_STATUS is None:
        return JSONResponse({"active": False, "seconds_remaining": 0, "enabled_by": None,
                             "warning": "Response guard not wired (non-gateway context)"})
    return JSONResponse(_OVERRIDE_GET_STATUS(case_dir_str))


async def post_response_guard_override(request: Request) -> JSONResponse:
    """Enable response-guard override with HMAC confirmation (default TTL: 10 min).

    Body: {challenge_id, response, ttl_seconds?}
    """
    role_err = _require_examiner_role(request)
    if role_err:
        return role_err

    case_dir_str = _active_case_dir_str()
    if not case_dir_str:
        return _no_case_response()

    examiner = _resolve_examiner(request)
    if not examiner:
        return JSONResponse({"error": "No examiner identity"}, status_code=401)

    err = _must_reset_check(examiner)
    if err:
        return err

    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"error": "Invalid JSON"}, status_code=400)

    challenge_id = str(body.get("challenge_id", ""))
    response_hmac = str(body.get("response", ""))
    ttl = int(body.get("ttl_seconds", _DEFAULT_OVERRIDE_TTL))

    if not challenge_id or not response_hmac:
        return JSONResponse({"error": "Missing challenge_id or response"}, status_code=400)
    if ttl < 1 or ttl > 3600:
        return JSONResponse({"error": "ttl_seconds must be 1–3600"}, status_code=400)

    err_msg, _ = _verify_evidence_hmac(examiner, challenge_id, response_hmac, request.client.host)
    if err_msg:
        return JSONResponse({"error": err_msg}, status_code=401)

    if _OVERRIDE_ENABLE is None:
        return JSONResponse({"error": "Response guard not wired"}, status_code=503)

    status = _OVERRIDE_ENABLE(case_dir_str, examiner, ttl)
    logger.warning(
        "response_guard override ENABLED: examiner=%s case=%s ttl=%ds",
        examiner, case_dir_str, ttl,
    )
    return JSONResponse({"enabled": True, **status})


async def post_response_guard_override_cancel(request: Request) -> JSONResponse:
    """Cancel an active response-guard override. Session auth only (no HMAC)."""
    role_err = _require_examiner_role(request)
    if role_err:
        return role_err

    case_dir_str = _active_case_dir_str()
    examiner = _resolve_examiner(request)

    if _OVERRIDE_CANCEL is None:
        return JSONResponse({"error": "Response guard not wired"}, status_code=503)

    _OVERRIDE_CANCEL(case_dir_str)
    logger.info("response_guard override CANCELLED: examiner=%s case=%s", examiner, case_dir_str)
    return JSONResponse({"cancelled": True})


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
    log_path = case_approvals_path(case_dir)
    log_path.parent.mkdir(parents=True, exist_ok=True)
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


def _apply_delta_db(request: Request, case_dir: Path, examiner: str, reviewer) -> dict:
    """Apply the pending review delta to DB authority (BATCH-K2).

    Reads the operator's queued decisions from pending-reviews.json (UI staging
    only — not authority), records the re-auth audit event, and applies the
    approve/reject/edit transition to Postgres via the injected investigation
    service. The DB rows (status, content hash, version, re-auth id) are
    authority; the case JSON is a mirror/export. The delta file is cleared on
    success so the queue does not re-apply.
    """
    delta_path = case_dir / "pending-reviews.json"
    if not delta_path.exists():
        raise ValueError("No pending reviews to commit")
    delta = json.loads(delta_path.read_text())
    items_list = delta.get("items", []) if isinstance(delta, dict) else []
    if not items_list:
        raise ValueError("No items in delta")

    case_id = _active_case_id()
    if not case_id:
        raise ValueError("No active case for DB review")

    # The challenge/response already authenticated the operator; record it as the
    # re-auth audit event that authorizes this review batch.
    reauth_id = _record_reauth_event(request, examiner, "review_commit")

    actions: list[dict] = []
    for entry in items_list:
        if not isinstance(entry, dict):
            continue
        actions.append(
            {
                "id": entry.get("id", ""),
                "action": entry.get("action", ""),
                "modifications": entry.get("modifications") or {},
                "note": entry.get("note"),
                "rejection_reason": entry.get("rejection_reason")
                or entry.get("reason"),
                "content_hash_at_review": entry.get("content_hash_at_review"),
                "version_at_review": entry.get("version_at_review"),
            }
        )

    result = reviewer(
        case_id=case_id,
        actions=actions,
        examiner=examiner,
        reauth_audit_event_id=reauth_id,
        actor=_request_principal(request),
    )

    # Clear the staged delta now that the authoritative transition committed.
    try:
        delta_path.unlink(missing_ok=True)
        (case_dir / "pending-reviews.processing").unlink(missing_ok=True)
    except OSError:
        pass

    summary = dict(result) if isinstance(result, dict) else {}
    summary.setdefault("authority", "db")
    return summary


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


def _db_investigation_list(method: str) -> list | None:
    """Read findings/timeline/iocs/todos from DB authority (_INVESTIGATION_DB).

    Returns None when no DB investigation service is wired or there is no active
    case, so the caller falls back to the file-backed path. Agent-authored rows
    keep their DB status (DRAFT/PROPOSED) so the portal renders them as proposed
    until a human acts. Never surfaces absolute paths.
    """
    if _INVESTIGATION_DB is None:
        return None
    case_id = _active_case_id()
    if not case_id:
        return None
    fn = getattr(_INVESTIGATION_DB, method, None)
    if not callable(fn):
        return None
    try:
        rows = fn(case_id)
    except Exception as exc:
        logger.warning("DB investigation %s failed: %s", method, exc)
        return None
    return rows if isinstance(rows, list) else []


async def get_findings(request: Request) -> JSONResponse:
    examiner = _resolve_examiner(request)
    if not examiner:
        return JSONResponse({"error": "Authentication required"}, status_code=401)
    role_err = _require_portal_role(request)
    if role_err:
        return role_err

    db_rows = _db_investigation_list("list_findings")
    if db_rows is not None:
        return JSONResponse(db_rows)

    case_dir = _resolve_case_dir()
    if not case_dir:
        return _no_case_response()
    findings = _load_json(case_dir / "findings.json") or []
    verified = _verify_items(case_dir, findings)
    return JSONResponse(verified)


async def get_finding_by_id(request: Request) -> JSONResponse:
    examiner = _resolve_examiner(request)
    if not examiner:
        return JSONResponse({"error": "Authentication required"}, status_code=401)
    role_err = _require_portal_role(request)
    if role_err:
        return role_err

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
    examiner = _resolve_examiner(request)
    if not examiner:
        return JSONResponse({"error": "Authentication required"}, status_code=401)
    role_err = _require_portal_role(request)
    if role_err:
        return role_err

    db_rows = _db_investigation_list("list_timeline")
    if db_rows is not None:
        return JSONResponse(db_rows)

    case_dir = _resolve_case_dir()
    if not case_dir:
        return _no_case_response()
    timeline = _load_json(case_dir / "timeline.json") or []
    verified = _verify_items(case_dir, timeline)
    return JSONResponse(verified)


async def get_evidence(request: Request) -> JSONResponse:
    examiner = _resolve_examiner(request)
    if not examiner:
        return JSONResponse({"error": "Authentication required"}, status_code=401)
    role_err = _require_portal_role(request)
    if role_err:
        return role_err

    # DB-authority path (C1): list evidence objects + custody/seal status from
    # Postgres. Only relative display paths and seal/custody fields are returned.
    if _EVIDENCE_DB is not None:
        lister = getattr(_EVIDENCE_DB, "list_evidence", None)
        case_id = _active_case_id()
        if callable(lister) and case_id:
            try:
                items = lister(case_id) or []
            except Exception as exc:
                return _active_case_error_response(exc, default=500)
            evidence = [
                {
                    "evidence_id": e.get("evidence_id") or e.get("id"),
                    "path": e.get("display_path", ""),
                    "display_name": e.get("display_name", ""),
                    "sha256": e.get("current_sha256") or "",
                    "size_bytes": e.get("current_bytes"),
                    "source": e.get("source", ""),
                    "description": e.get("description", ""),
                    "status": e.get("status", "detected"),
                    "seal_status": e.get("seal_status", "unsealed"),
                    "registered_at": e.get("registered_at", ""),
                    "sealed_at": e.get("sealed_at", ""),
                    "referenced_by": e.get("referenced_by", []),
                }
                for e in items
                if isinstance(e, dict)
            ]
            return JSONResponse(evidence)

    # DB custody authority only. With no DB evidence service or no active case
    # (fresh install) the evidence list degrades gracefully to empty — never a
    # file read, never 404/500.
    return JSONResponse([])


async def get_audit_for_finding(request: Request) -> JSONResponse:
    examiner = _resolve_examiner(request)
    if not examiner:
        return JSONResponse({"error": "Authentication required"}, status_code=401)
    role_err = _require_portal_role(request)
    if role_err:
        return role_err

    finding_id = request.path_params["finding_id"]

    # BATCH-K6: in DB-active mode the finding and its audit trail are Postgres
    # authority. Source the finding's audit_ids from the DB investigation record
    # and the audit entries from app.audit_events — never from findings.json or
    # the audit/*.jsonl mirror — so tampering with or deleting those files cannot
    # spoof, hide, or fabricate the audit trail shown for a finding.
    if _db_investigation_active():
        case_id = _active_case_id()
        finding = None
        for f in _INVESTIGATION_DB.list_findings(case_id):
            if f.get("id") == finding_id:
                finding = f
                break
        if not finding:
            return JSONResponse([])
        audit_ids = set(finding.get("audit_ids", []))
        for art in finding.get("artifacts", []):
            for step in art.get("provenance_chain", []):
                if step.get("audit_id"):
                    audit_ids.add(step["audit_id"])
        if not audit_ids:
            return JSONResponse([])
        reader = getattr(_INVESTIGATION_DB, "audit_events", None)
        if not callable(reader):
            return JSONResponse([])
        events = reader(case_id, sorted(audit_ids))
        for ev in events:
            ev["_backend"] = ev.get("source", "db")
        return JSONResponse(events)

    case_dir = _resolve_case_dir()
    if not case_dir:
        return _no_case_response()

    # Legacy (non-DB) mode only: get the finding's audit_ids from findings.json
    findings = _load_json(case_dir / "findings.json") or []
    audit_ids = set()
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
    audit_dir = case_audit_dir(case_dir)
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
    examiner = _resolve_examiner(request)
    if not examiner:
        return JSONResponse({"error": "Authentication required"}, status_code=401)
    role_err = _require_portal_role(request)
    if role_err:
        return role_err

    case_dir = _resolve_case_dir()
    if not case_dir:
        return _no_case_response()
    delta = _load_json(case_dir / "pending-reviews.json")
    if delta is None:
        return JSONResponse({"items": []})
    return JSONResponse(delta)


async def get_case(request: Request) -> JSONResponse:
    examiner = _resolve_examiner(request)
    if not examiner:
        return JSONResponse({"error": "Authentication required"}, status_code=401)
    role_err = _require_portal_role(request)
    if role_err:
        return role_err

    if _ACTIVE_CASES is not None:
        try:
            principal = _request_principal(request)
            require_active = getattr(_ACTIVE_CASES, "require_active_case_for_principal", None)
            if principal is not None and callable(require_active):
                case = require_active(principal)
            else:
                case = _ACTIVE_CASES.get_active_case(principal)
            return JSONResponse(case.as_dict())
        except Exception as exc:
            return _active_case_error_response(exc)

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


async def post_case_metadata(request: Request) -> JSONResponse:
    """Set a single case metadata field.

    Examiner-triggered, portal-owned (F-E): metadata setting and report
    generation are not on the agent MCP surface. Validation/persistence live
    in sift_core.case_metadata; this route is the operator-facing trigger.
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
        return JSONResponse({"error": "Invalid JSON body"}, status_code=400)
    if not isinstance(body, dict):
        return JSONResponse({"error": "Request body must be a JSON object"}, status_code=400)

    if _ACTIVE_CASES is not None:
        try:
            active = _ACTIVE_CASES.get_active_case(_request_principal(request))
            updated = _ACTIVE_CASES.update_case_metadata(
                active.case_id, _request_principal(request), body
            )
            return JSONResponse(updated.as_dict())
        except Exception as exc:
            return _active_case_error_response(exc)

    case_dir = _resolve_case_dir()
    if not case_dir:
        return _no_case_response()

    field = body.get("field")
    if not isinstance(field, str) or not field.strip():
        return JSONResponse({"error": "'field' is required"}, status_code=400)
    value = body.get("value", "")

    from sift_core.case_metadata import set_case_metadata
    try:
        result = set_case_metadata(case_dir, field.strip(), value)
    except ValueError as e:
        return JSONResponse({"error": str(e)}, status_code=400)
    except OSError as e:
        logger.exception("Failed to write case metadata for %s: %s", case_dir.name, e)
        return JSONResponse({"error": "Failed to write case metadata."}, status_code=500)

    if "error" in result:
        return JSONResponse(result, status_code=400)
    return JSONResponse(result)


async def get_todos(request: Request) -> JSONResponse:
    examiner = _resolve_examiner(request)
    if not examiner:
        return JSONResponse({"error": "Authentication required"}, status_code=401)
    role_err = _require_portal_role(request)
    if role_err:
        return role_err

    db_rows = _db_investigation_list("list_todos")
    if db_rows is not None:
        return JSONResponse(db_rows)

    case_dir = _resolve_case_dir()
    if not case_dir:
        return _no_case_response()
    todos = _load_json(case_dir / "todos.json") or []
    return JSONResponse(todos)


_TODO_PRIORITIES = ("high", "medium", "low")
_TODO_STATUSES = ("open", "completed")
_MAX_TODO_DESC = 2000


def _write_todos(case_dir: Path, todos: list) -> JSONResponse | None:
    """Atomically persist todos.json. Returns an error response on failure, else None.

    Mirrors the forensic-mcp writer (plain todos.json, no chmod-444) but adds the
    portal's symlink guard and atomic temp-file + rename used by post_delta.
    """
    todos_path = case_dir / "todos.json"
    if todos_path.exists() and os.path.islink(todos_path):
        return JSONResponse(
            {"error": "Refusing to write: target is a symlink"},
            status_code=403,
        )
    try:
        tmp_fd, tmp_path = tempfile.mkstemp(dir=str(case_dir), suffix=".tmp")
        try:
            with os.fdopen(tmp_fd, "w", encoding="utf-8") as f:
                json.dump(todos, f, indent=2, default=str)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp_path, str(todos_path))
        except Exception:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
            raise
    except OSError as e:
        logger.error("Failed to write todos file: %s", e)
        return JSONResponse({"error": "Write failed"}, status_code=500)
    return None


def _sync_local_reauth_password(examiner: str | None, password: str) -> None:
    """Keep the MVP local HMAC reauth bridge aligned with Supabase login.

    Supabase is the login authority, but evidence seal/verify, review commit,
    report inclusion, and response-guard override still use the local PBKDF2
    challenge bridge in this MVP. Store only the salted verifier, never the raw
    password, so the same operator password works for both login and reauth.
    """
    if not examiner or not password:
        return
    salt = secrets.token_bytes(32)
    pw_hash = hashlib.pbkdf2_hmac(
        "sha256", password.encode(), salt, 600_000
    ).hex()
    existing = _load_pw_entry(_PASSWORDS_DIR, examiner) or {}
    entry = {
        **existing,
        "hash": pw_hash,
        "salt": salt.hex(),
        "must_reset_password": False,
        "role": existing.get("role", "examiner"),
    }
    _save_pw_entry(_PASSWORDS_DIR, examiner, entry)


def _principal_examiner_name(principal: dict) -> str | None:
    """Return the local examiner name used by legacy HMAC reauth files."""
    if not isinstance(principal, dict) or principal.get("principal_type") != "operator":
        return None
    return (
        principal.get("display_name")
        or principal.get("email")
        or principal.get("principal_id")
    )


async def _read_todo_body(request: Request) -> tuple[dict | None, JSONResponse | None]:
    """Size-check, read and JSON-parse a todo request body into a dict."""
    content_length = request.headers.get("content-length")
    try:
        if content_length and int(content_length) > _MAX_DELTA_SIZE:
            return None, JSONResponse(
                {"error": "Request body too large (max 1 MB)"}, status_code=413
            )
    except ValueError:
        pass
    body = await request.body()
    if len(body) > _MAX_DELTA_SIZE:
        return None, JSONResponse(
            {"error": "Request body too large (max 1 MB)"}, status_code=413
        )
    if not body:
        return {}, None
    try:
        data = json.loads(body)
    except json.JSONDecodeError:
        return None, JSONResponse({"error": "Invalid JSON"}, status_code=400)
    if not isinstance(data, dict):
        return None, JSONResponse({"error": "Expected JSON object"}, status_code=400)
    return data, None


def _validate_related_findings(value) -> tuple[list | None, JSONResponse | None]:
    if value is None:
        return [], None
    if not isinstance(value, list) or not all(isinstance(x, str) for x in value):
        return None, JSONResponse(
            {"error": "'related_findings' must be a list of strings"}, status_code=400
        )
    return value, None


async def post_todo(request: Request) -> JSONResponse:
    """Create a TODO. Direct write — todos are operational tasks, not evidentiary findings."""
    role_err = _require_examiner_role(request)
    if role_err:
        return role_err
    case_dir = _resolve_case_dir()
    if not case_dir and not _db_investigation_active():
        return _no_case_response()
    examiner = _resolve_examiner(request)
    if not examiner:
        return JSONResponse({"error": "Authentication required"}, status_code=401)
    err = _must_reset_check(examiner)
    if err:
        return err

    data, body_err = await _read_todo_body(request)
    if body_err:
        return body_err

    description = (data.get("description") or "").strip()
    if not description:
        return JSONResponse({"error": "'description' is required"}, status_code=400)
    if len(description) > _MAX_TODO_DESC:
        return JSONResponse(
            {"error": f"'description' too long (max {_MAX_TODO_DESC} chars)"},
            status_code=400,
        )
    priority = data.get("priority") or "medium"
    if priority not in _TODO_PRIORITIES:
        return JSONResponse(
            {"error": f"'priority' must be one of {_TODO_PRIORITIES}"}, status_code=400
        )
    related, rel_err = _validate_related_findings(data.get("related_findings"))
    if rel_err:
        return rel_err
    assignee = data.get("assignee") or ""
    if not isinstance(assignee, str):
        return JSONResponse({"error": "'assignee' must be a string"}, status_code=400)

    # DB-authority path: TODOs are operator-owned operational tasks. The DB
    # service assigns the id and persists; agents never reach this route (B1).
    if _INVESTIGATION_DB is not None:
        creator = getattr(_INVESTIGATION_DB, "create_todo", None)
        case_id = _active_case_id()
        if callable(creator) and case_id:
            try:
                todo = creator(
                    case_id=case_id,
                    examiner=examiner,
                    actor=_request_principal(request),
                    description=description,
                    priority=priority,
                    assignee=assignee,
                    related_findings=related,
                )
            except Exception as exc:
                return _active_case_error_response(exc, default=500)
            return JSONResponse(todo if isinstance(todo, dict) else {}, status_code=201)

    todos = _load_json(case_dir / "todos.json") or []
    if not isinstance(todos, list):
        return JSONResponse({"error": "Corrupt todos.json"}, status_code=500)

    # Match the forensic-mcp ID scheme: TODO-{examiner}-NNN, per-examiner sequence.
    prefix = f"TODO-{examiner}-"
    max_num = 0
    for t in todos:
        tid = t.get("todo_id", "") if isinstance(t, dict) else ""
        if tid.startswith(prefix):
            try:
                max_num = max(max_num, int(tid[len(prefix):]))
            except ValueError:
                pass
    todo_id = f"{prefix}{max_num + 1:03d}"

    todo = {
        "todo_id": todo_id,
        "description": description,
        "status": "open",
        "priority": priority,
        "assignee": assignee,
        "related_findings": related,
        "created_by": examiner,
        "examiner": examiner,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "notes": [],
        "completed_at": None,
    }
    todos.append(todo)
    write_err = _write_todos(case_dir, todos)
    if write_err:
        return write_err
    return JSONResponse(todo, status_code=201)


async def patch_todo(request: Request) -> JSONResponse:
    """Update a TODO (description, priority, status, assignee, related_findings, note)."""
    role_err = _require_examiner_role(request)
    if role_err:
        return role_err
    case_dir = _resolve_case_dir()
    if not case_dir and not _db_investigation_active():
        return _no_case_response()
    examiner = _resolve_examiner(request)
    if not examiner:
        return JSONResponse({"error": "Authentication required"}, status_code=401)
    err = _must_reset_check(examiner)
    if err:
        return err

    data, body_err = await _read_todo_body(request)
    if body_err:
        return body_err

    todo_id = request.path_params["todo_id"]

    # Validate inputs up front so the DB path and file path share one contract.
    if "priority" in data and data["priority"] not in _TODO_PRIORITIES:
        return JSONResponse(
            {"error": f"'priority' must be one of {_TODO_PRIORITIES}"}, status_code=400
        )
    if "status" in data and data["status"] not in _TODO_STATUSES:
        return JSONResponse(
            {"error": f"'status' must be one of {_TODO_STATUSES}"}, status_code=400
        )
    if "description" in data and not (data.get("description") or "").strip():
        return JSONResponse({"error": "'description' cannot be empty"}, status_code=400)

    if _INVESTIGATION_DB is not None:
        updater = getattr(_INVESTIGATION_DB, "update_todo", None)
        case_id = _active_case_id()
        if callable(updater) and case_id:
            try:
                todo = updater(
                    case_id=case_id,
                    todo_id=todo_id,
                    examiner=examiner,
                    actor=_request_principal(request),
                    patch=data,
                )
            except Exception as exc:
                return _active_case_error_response(exc, default=500)
            if not todo:
                return JSONResponse({"error": "TODO not found"}, status_code=404)
            return JSONResponse(todo)

    todos = _load_json(case_dir / "todos.json") or []
    if not isinstance(todos, list):
        return JSONResponse({"error": "Corrupt todos.json"}, status_code=500)

    todo = next(
        (t for t in todos if isinstance(t, dict) and t.get("todo_id") == todo_id), None
    )
    if todo is None:
        return JSONResponse({"error": "TODO not found"}, status_code=404)

    if "description" in data:
        description = (data.get("description") or "").strip()
        if not description:
            return JSONResponse(
                {"error": "'description' cannot be empty"}, status_code=400
            )
        if len(description) > _MAX_TODO_DESC:
            return JSONResponse(
                {"error": f"'description' too long (max {_MAX_TODO_DESC} chars)"},
                status_code=400,
            )
        todo["description"] = description
    if "priority" in data:
        if data["priority"] not in _TODO_PRIORITIES:
            return JSONResponse(
                {"error": f"'priority' must be one of {_TODO_PRIORITIES}"},
                status_code=400,
            )
        todo["priority"] = data["priority"]
    if "status" in data:
        if data["status"] not in _TODO_STATUSES:
            return JSONResponse(
                {"error": f"'status' must be one of {_TODO_STATUSES}"}, status_code=400
            )
        todo["status"] = data["status"]
        todo["completed_at"] = (
            datetime.now(timezone.utc).isoformat()
            if data["status"] == "completed"
            else None
        )
    if "assignee" in data:
        if not isinstance(data["assignee"], str):
            return JSONResponse(
                {"error": "'assignee' must be a string"}, status_code=400
            )
        todo["assignee"] = data["assignee"]
    if "related_findings" in data:
        related, rel_err = _validate_related_findings(data["related_findings"])
        if rel_err:
            return rel_err
        todo["related_findings"] = related
    if data.get("note"):
        if not isinstance(data["note"], str):
            return JSONResponse({"error": "'note' must be a string"}, status_code=400)
        todo.setdefault("notes", []).append(
            {
                "note": data["note"],
                "by": examiner,
                "at": datetime.now(timezone.utc).isoformat(),
            }
        )

    write_err = _write_todos(case_dir, todos)
    if write_err:
        return write_err
    return JSONResponse(todo)


async def delete_todo(request: Request) -> JSONResponse:
    """Delete a TODO by id."""
    role_err = _require_examiner_role(request)
    if role_err:
        return role_err
    case_dir = _resolve_case_dir()
    if not case_dir and not _db_investigation_active():
        return _no_case_response()
    examiner = _resolve_examiner(request)
    if not examiner:
        return JSONResponse({"error": "Authentication required"}, status_code=401)
    err = _must_reset_check(examiner)
    if err:
        return err

    todo_id = request.path_params["todo_id"]

    if _INVESTIGATION_DB is not None:
        deleter = getattr(_INVESTIGATION_DB, "delete_todo", None)
        case_id = _active_case_id()
        if callable(deleter) and case_id:
            try:
                ok = deleter(
                    case_id=case_id,
                    todo_id=todo_id,
                    examiner=examiner,
                    actor=_request_principal(request),
                )
            except Exception as exc:
                return _active_case_error_response(exc, default=500)
            if not ok:
                return JSONResponse({"error": "TODO not found"}, status_code=404)
            return JSONResponse({"status": "deleted", "todo_id": todo_id})

    todos = _load_json(case_dir / "todos.json") or []
    if not isinstance(todos, list):
        return JSONResponse({"error": "Corrupt todos.json"}, status_code=500)

    remaining = [
        t for t in todos if not (isinstance(t, dict) and t.get("todo_id") == todo_id)
    ]
    if len(remaining) == len(todos):
        return JSONResponse({"error": "TODO not found"}, status_code=404)

    write_err = _write_todos(case_dir, remaining)
    if write_err:
        return write_err
    return JSONResponse({"status": "deleted", "todo_id": todo_id})


async def get_iocs(request: Request) -> JSONResponse:
    examiner = _resolve_examiner(request)
    if not examiner:
        return JSONResponse({"error": "Authentication required"}, status_code=401)
    role_err = _require_portal_role(request)
    if role_err:
        return role_err

    db_rows = _db_investigation_list("list_iocs")
    if db_rows is not None:
        return JSONResponse(db_rows)

    case_dir = _resolve_case_dir()
    if not case_dir:
        return _no_case_response()
    iocs_path = case_dir / "iocs.json"
    if not iocs_path.exists():
        return JSONResponse([])
    return JSONResponse(_load_json(iocs_path) or [])


async def get_summary(request: Request) -> JSONResponse:
    examiner = _resolve_examiner(request)
    if not examiner:
        return JSONResponse({"error": "Authentication required"}, status_code=401)
    role_err = _require_portal_role(request)
    if role_err:
        return role_err

    case_dir = _resolve_case_dir()
    if not case_dir:
        return _no_case_response()

    findings = _load_json(case_dir / "findings.json") or []
    timeline = _load_json(case_dir / "timeline.json") or []
    todos = _load_json(case_dir / "todos.json") or []

    # Evidence count comes from DB custody authority (never the legacy
    # evidence.json state file). On a fresh install / no DB it is simply 0.
    evidence_total = 0
    if _EVIDENCE_DB is not None:
        lister = getattr(_EVIDENCE_DB, "list_evidence", None)
        case_id = _active_case_id()
        if callable(lister) and case_id:
            try:
                evidence_total = len(lister(case_id) or [])
            except Exception as exc:
                logger.warning("DB list_evidence for summary failed: %s", exc)

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
            "evidence": {"total": evidence_total},
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

    examiner = _resolve_examiner(request)
    if not examiner:
        return JSONResponse({"error": "Authentication required"}, status_code=401)
    err = _must_reset_check(examiner)
    if err:
        return err

    req_path = unquote(request.path_params["path"])

    if _EVIDENCE_DB is not None:
        case_id = _active_case_id()
        verifier = getattr(_EVIDENCE_DB, "verify", None)
        lister = getattr(_EVIDENCE_DB, "list_evidence", None)
        if case_id and callable(verifier) and callable(lister):
            try:
                registered = lister(case_id)
                known = {
                    str(item.get("display_path") or item.get("path") or "")
                    for item in registered
                    if isinstance(item, dict)
                }
                if req_path not in known:
                    return JSONResponse(
                        {"error": f"Not in evidence registry: {req_path}"},
                        status_code=404,
                    )
                result = verifier(case_id=case_id, actor=_request_principal(request))
            except Exception as exc:
                logger.warning("DB evidence verify failed: %s", type(exc).__name__)
                return JSONResponse(
                    {"error": "Evidence verification failed — check gateway logs"},
                    status_code=500,
                )
            issues = result.get("issues") if isinstance(result, dict) else []
            issue_list = issues if isinstance(issues, list) else []
            matching_issues = [str(issue) for issue in issue_list if req_path in str(issue)]
            verified = bool(result.get("verified")) if isinstance(result, dict) else False
            status = "failed" if matching_issues or not verified else "verified"
            return JSONResponse(
                {
                    "path": req_path,
                    "status": status,
                    "issues": matching_issues,
                    "authority": "db",
                }
            )

    # DB custody authority only. The legacy evidence.json registry / file-hash
    # fallback has been removed; without DB authority (fresh install) there is no
    # evidence registry to verify against, so degrade gracefully to no_case.
    return _no_case_response()


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
            {"error": "No password configured. Run: sift config --setup-password"},
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

    # BATCH-K2: in DB-active mode the approve/reject/edit transition is applied to
    # Postgres authority (content-hash/version guarded, atomic) and the case JSON
    # is no longer the authority for report eligibility. The successful
    # password/HMAC challenge above is the operator re-auth; record it as an audit
    # event and pass its id into the DB review so the human decision is provenance
    # linked. Falls through to the file path only when DB authority is not wired.
    if _db_investigation_active():
        reviewer = getattr(_INVESTIGATION_DB, "apply_review", None)
        if callable(reviewer):
            try:
                result = _apply_delta_db(request, case_dir, examiner, reviewer)
            except Exception:
                logger.exception("DB commit failed")
                return JSONResponse(
                    {"error": "Commit failed — check gateway logs"}, status_code=500
                )
            return JSONResponse(result)

    # Apply delta (mirrors _review_mode)
    try:
        result = _apply_delta(case_dir, examiner, stored_hash)
    except Exception:
        logger.exception("Commit failed")
        return JSONResponse({"error": "Commit failed — check gateway logs"}, status_code=500)

    return JSONResponse(result)


# ---- Phase 12d: Auth endpoints ----


async def get_auth_setup_required(request: Request) -> JSONResponse:
    """No auth required. Returns whether first-time password setup is needed."""
    if _legacy_password_auth_disabled():
        return JSONResponse({"required": False, "setup_required": False})

    try:
        has_any = _PASSWORDS_DIR.is_dir() and any(_PASSWORDS_DIR.glob("*.json"))
    except OSError:
        has_any = False
    required = not has_any
    return JSONResponse({"required": required, "setup_required": required})


async def post_auth_setup(request: Request) -> JSONResponse:
    """Create the first examiner account. Only available when no passwords exist."""
    if _legacy_password_auth_disabled():
        return _legacy_password_auth_disabled_response()

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
    if _legacy_password_auth_disabled():
        return _legacy_password_auth_disabled_response()

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


def _http_status_from_callback_error(exc: Exception, default: int = 500) -> int:
    """Map a Supabase-auth callback exception to an HTTP status (C3 contract).

    The injected supabase_auth raises exceptions carrying int .http_status and
    str .reason; everything else maps to ``default``. Never includes token
    material in the response.
    """
    status = getattr(exc, "http_status", None)
    if isinstance(status, int) and 400 <= status <= 599:
        return status
    return default


def _principal_profile(principal: dict) -> dict:
    """Public, token-free operator profile shape for /api/auth/me responses."""
    if not isinstance(principal, dict):
        return {}
    memberships = principal.get("case_memberships") or []
    safe_memberships = [
        {"case_id": m.get("case_id"), "role": m.get("role")}
        for m in memberships
        if isinstance(m, dict)
    ]
    return {
        "principal_type": principal.get("principal_type"),
        "principal_id": principal.get("principal_id"),
        "auth_user_id": principal.get("auth_user_id"),
        "display_name": principal.get("display_name"),
        "email": principal.get("email"),
        "system_role": principal.get("system_role"),
        "status": principal.get("status"),
        "case_memberships": safe_memberships,
    }


def _clear_envelope_cookie_response(body: dict, status_code: int) -> JSONResponse:
    """Build a JSON response that clears the Supabase session-envelope cookie."""
    resp = JSONResponse(body, status_code=status_code)
    resp.set_cookie(
        SESSION_ENVELOPE_COOKIE_NAME,
        "",
        max_age=0,
        path=SESSION_ENVELOPE_COOKIE_PATH,
        httponly=True,
        secure=True,
        samesite=SESSION_ENVELOPE_COOKIE_SAME_SITE,
    )
    return resp


async def post_supabase_login(request: Request) -> JSONResponse:
    """PR03A — email/password login via the Gateway Supabase callback.

    On success sets the signed, Secure/HttpOnly/SameSite session-envelope cookie
    carrying the Supabase access/refresh tokens. Token material is never returned
    in the JSON body or logged. Only operator principals succeed (the callback
    raises http_status=403 for agent/service).
    """
    if _SUPABASE_AUTH is None:
        return JSONResponse({"error": "Supabase auth not configured"}, status_code=503)
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

    email = str(body.get("email", "")).strip()
    password = str(body.get("password", ""))
    if not email or not password:
        return JSONResponse({"error": "Missing email or password"}, status_code=400)

    source_ip = request.client.host if request.client else "unknown"
    try:
        result = await _SUPABASE_AUTH.login(email, password, source_ip)
    except Exception as exc:  # noqa: BLE001 - never leak token material
        status = _http_status_from_callback_error(exc, default=401)
        reason = getattr(exc, "reason", None)
        msg = reason if isinstance(reason, str) and reason else "Invalid credentials"
        return JSONResponse({"error": msg}, status_code=status)

    if not result:
        return JSONResponse({"error": "Invalid credentials"}, status_code=401)

    principal = result.get("principal") or {}
    envelope = generate_session_envelope(
        access_token=result.get("access_token", ""),
        refresh_token=result.get("refresh_token", ""),
        expires_at=int(result.get("expires_at", 0)),
        sub=result.get("sub", ""),
        fingerprint=result.get("fingerprint", ""),
        secret=_SESSION_SECRET,
    )

    # A1-BOOTSTRAP: signal forced reset when the operator was provisioned by the
    # installer with status='invited'. The portal must present a password-reset
    # screen before allowing any other action. Token material is not in the body.
    principal_status = principal.get("status", "active")
    must_reset = principal_status == "invited"
    if not must_reset:
        try:
            _sync_local_reauth_password(_principal_examiner_name(principal), password)
        except OSError as exc:
            logger.warning("local reauth password sync failed: %s", type(exc).__name__)

    resp = JSONResponse({
        "ok": True,
        "principal": _principal_profile(principal),
        "must_reset": must_reset,  # A1-BOOTSTRAP: installer handoff forced-reset signal
    })
    resp.set_cookie(
        SESSION_ENVELOPE_COOKIE_NAME,
        envelope,
        max_age=_SESSION_MAX_AGE,
        path=SESSION_ENVELOPE_COOKIE_PATH,
        httponly=True,
        secure=True,
        samesite=SESSION_ENVELOPE_COOKIE_SAME_SITE,
    )
    return resp


async def post_supabase_refresh(request: Request) -> JSONResponse:
    """PR03A — explicit refresh: rotate the session envelope from its refresh token."""
    if _SUPABASE_AUTH is None:
        return JSONResponse({"error": "Supabase auth not configured"}, status_code=503)
    if not _SESSION_SECRET:
        return JSONResponse({"error": "Portal session not configured"}, status_code=500)

    cookie_val = request.cookies.get(SESSION_ENVELOPE_COOKIE_NAME)
    envelope = verify_session_envelope(cookie_val, _SESSION_SECRET) if cookie_val else None
    if not envelope or not envelope.get("rt"):
        return JSONResponse({"error": "No session to refresh"}, status_code=401)

    source_ip = request.client.host if request.client else "unknown"
    try:
        result = await _SUPABASE_AUTH.refresh(envelope["rt"], source_ip)
    except Exception as exc:  # noqa: BLE001
        # Fail closed: a raising refresh (e.g. revoked session) must drop the
        # cookie, not just report 401 (C10.1).
        status = _http_status_from_callback_error(exc, default=401)
        return _clear_envelope_cookie_response(
            {"error": "Session refresh failed"}, status_code=status
        )

    if not result:
        # Fail closed: clear the envelope cookie.
        return _clear_envelope_cookie_response(
            {"error": "Session refresh failed"}, status_code=401
        )

    principal = result.get("principal") or {}
    # Refresh is for operator portal sessions only (C10.2). Agent/service JWTs use
    # /mcp, never the portal session-envelope cookie.
    if not isinstance(principal, dict) or principal.get("principal_type") != "operator":
        return _clear_envelope_cookie_response(
            {"error": "Session refresh failed"}, status_code=401
        )

    new_envelope = generate_session_envelope(
        access_token=result.get("access_token", ""),
        refresh_token=result.get("refresh_token", ""),
        expires_at=int(result.get("expires_at", 0)),
        sub=result.get("sub", envelope.get("sub", "")),
        fingerprint=result.get("fingerprint", ""),
        secret=_SESSION_SECRET,
        # Preserve the original issued-at so the absolute ceiling is not reset.
        issued_at=envelope.get("eiat"),
    )
    resp = JSONResponse({"ok": True, "principal": _principal_profile(principal)})
    resp.set_cookie(
        SESSION_ENVELOPE_COOKIE_NAME, new_envelope, max_age=_SESSION_MAX_AGE,
        path=SESSION_ENVELOPE_COOKIE_PATH, httponly=True, secure=True,
        samesite=SESSION_ENVELOPE_COOKIE_SAME_SITE,
    )
    return resp


async def post_supabase_forced_reset(request: Request) -> JSONResponse:
    """POST /portal/api/auth/forced-reset — A1-BOOTSTRAP: complete the installer forced-reset.

    Called when ``must_reset: true`` is returned on first login. Requires the
    current Supabase session envelope cookie (the operator is already
    authenticated with the temporary installer password). Sets the new permanent
    password via Admin API and transitions the operator from 'invited' to 'active'.

    Body: {new_password: string}
    Token material is never in the request/response body or logs.
    """
    if _SUPABASE_AUTH is None:
        return JSONResponse({"error": "Supabase auth not configured"}, status_code=503)
    if not _SESSION_SECRET:
        return JSONResponse({"error": "Portal session not configured"}, status_code=500)

    # Require an active session envelope — the operator must already be logged in.
    cookie_val = request.cookies.get(SESSION_ENVELOPE_COOKIE_NAME)
    if not cookie_val:
        return JSONResponse({"error": "Authentication required"}, status_code=401)
    envelope = verify_session_envelope(cookie_val, _SESSION_SECRET)
    if not envelope or not envelope.get("at"):
        return JSONResponse({"error": "Authentication required"}, status_code=401)

    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"error": "Invalid JSON"}, status_code=400)

    new_password = str(body.get("new_password", ""))
    if not new_password:
        return JSONResponse({"error": "Missing new_password"}, status_code=400)

    source_ip = request.client.host if request.client else "unknown"
    try:
        await _SUPABASE_AUTH.forced_reset(
            access_token=envelope["at"],
            new_password=new_password,
            source_ip=source_ip,
        )
    except Exception as exc:  # noqa: BLE001 - never leak token material
        status = _http_status_from_callback_error(exc, default=400)
        reason = getattr(exc, "reason", None)
        msg = reason if isinstance(reason, str) and reason else "Forced reset failed"
        return JSONResponse({"error": msg}, status_code=status)

    principal = getattr(request.state, "principal", None)
    try:
        _sync_local_reauth_password(
            _principal_examiner_name(principal or {}), new_password
        )
    except OSError as exc:
        logger.warning("local reauth password sync failed after forced reset: %s", type(exc).__name__)

    return JSONResponse({"ok": True, "must_reset": False})


async def post_auth_login(request: Request) -> JSONResponse:
    """Authenticate. PR03A: email/password Supabase when configured, else legacy.

    When the Gateway has injected ``supabase_auth`` the portal uses the Supabase
    email/password path. Otherwise it falls back to the legacy PBKDF2
    challenge-response (still used by tests and non-Supabase deployments).
    """
    if _SUPABASE_AUTH is not None:
        return await post_supabase_login(request)

    if not _LEGACY_PORTAL_SESSION_ENABLED:
        return JSONResponse({"error": "Legacy portal login disabled"}, status_code=403)

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
    if _legacy_password_auth_disabled():
        return _legacy_password_auth_disabled_response()

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
    """Clear the portal session cookie(s). PR03A: also tells Supabase to revoke.

    Clears both the legacy sift_session cookie (revoking its JTI) and the
    Supabase session-envelope cookie. When a Supabase callback is configured and
    a valid envelope is present, the access token is passed to supabase_auth.logout
    so the Gateway can revoke the upstream session. Token values are never logged.
    """
    # PR03A — Supabase session envelope logout.
    if _SESSION_SECRET:
        env_cookie = request.cookies.get(SESSION_ENVELOPE_COOKIE_NAME)
        if env_cookie:
            envelope = verify_session_envelope(env_cookie, _SESSION_SECRET)
            if envelope and _SUPABASE_AUTH is not None and envelope.get("at"):
                source_ip = request.client.host if request.client else "unknown"
                try:
                    await _SUPABASE_AUTH.logout(envelope["at"], source_ip)
                except Exception as exc:  # noqa: BLE001
                    logger.warning("portal logout callback failed: %s", type(exc).__name__)

    # Legacy sift_session JTI revocation.
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
    resp.set_cookie(
        SESSION_ENVELOPE_COOKIE_NAME,
        "",
        max_age=0,
        path=SESSION_ENVELOPE_COOKIE_PATH,
        httponly=True,
        secure=True,
        samesite=SESSION_ENVELOPE_COOKIE_SAME_SITE,
    )
    return resp


async def get_auth_me(request: Request) -> JSONResponse:
    """Return current session info, or 401 if not authenticated.

    PR03A: when the middleware resolved a Supabase app principal, return the
    operator profile + system_role + case memberships (no token material). Falls
    back to the legacy examiner/role/must_reset shape otherwise.
    """
    principal = getattr(request.state, "principal", None)
    if isinstance(principal, dict) and principal:
        profile = _principal_profile(principal)
        # Agent/service principals never authenticate operator portal APIs.
        if profile.get("principal_type") != "operator":
            return JSONResponse({"error": "Not authenticated"}, status_code=401)
        return JSONResponse(profile)

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

_V2_ASSET_MEDIA_TYPES = {
    ".js": "application/javascript",
    ".css": "text/css",
    ".png": "image/png",
    ".jpg": "image/jpeg",
    ".svg": "image/svg+xml",
    ".ico": "image/x-icon",
    ".woff": "font/woff",
    ".woff2": "font/woff2",
    ".ttf": "font/ttf",
}


async def serve_v2_assets(request: Request) -> Response:
    """Serve Vite build assets from static/v2/assets/ (hashed JS/CSS chunks)."""
    filename = request.path_params.get("filename", "")
    resolved = (_V2_STATIC_DIR / "assets" / filename).resolve()
    assets_root = (_V2_STATIC_DIR / "assets").resolve()
    if not str(resolved).startswith(str(assets_root)):
        return JSONResponse({"error": "not found"}, status_code=404)
    if not resolved.is_file():
        return JSONResponse({"error": "not found"}, status_code=404)
    media_type = _V2_ASSET_MEDIA_TYPES.get(resolved.suffix.lower(), "application/octet-stream")
    return FileResponse(resolved, media_type=media_type)


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
            "style-src 'unsafe-inline' https://fonts.googleapis.com; "
            "font-src https://fonts.gstatic.com; "
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

    if _TOKEN_REGISTRY is not None:
        try:
            tokens = _TOKEN_REGISTRY.list_tokens()
        except Exception as e:
            logger.error("Failed to list DB-backed tokens: %s", e)
            return JSONResponse({"error": "Failed to list tokens"}, status_code=500)
        return JSONResponse({"tokens": tokens, "count": len(tokens)})

    tokens = []
    for _raw_token, info in _API_KEYS.items():
        if not isinstance(info, dict):
            continue
        if info.get("role") not in ("agent", "readonly"):
            continue  # Skip examiner gateway tokens from this view
        tokens.append(_token_metadata(info))

    # Sort by created_at for stable output
    tokens.sort(key=lambda t: t.get("created_at") or "")
    return JSONResponse({"tokens": tokens, "count": len(tokens)})


async def create_token(request: Request) -> JSONResponse:
    """POST /api/tokens — create a new sift_svc_* service token.

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
    case_id = body.get("case_id")
    if case_id is not None:
        case_id = str(case_id).strip() or None
    if token_role == "agent" and case_id is None and _ACTIVE_CASES is not None:
        case_id = _active_case_id()
        if not case_id:
            return JSONResponse(
                {"error": "An active DB case is required before issuing an agent token"},
                status_code=409,
            )
    if expires_at is not None:
        try:
            datetime.fromisoformat(str(expires_at).replace("Z", "+00:00"))
        except ValueError:
            return JSONResponse({"error": "expires_at must be an ISO datetime"}, status_code=400)

    if _TOKEN_REGISTRY is None:
        return JSONResponse(
            {"error": "Token management unavailable: token registry not configured"},
            status_code=503,
        )

    from sift_gateway.token_gen import generate_service_token

    raw_token = generate_service_token()
    now_iso = _iso_now()

    try:
        record = _TOKEN_REGISTRY.create_token(
            raw_token=raw_token,
            agent_id=agent_id,
            label=label,
            role=token_role,
            created_by=examiner,
            expires_at=expires_at,
            case_id=case_id,
        )
    except ValueError as e:
        return JSONResponse({"error": str(e)}, status_code=409)
    except Exception as e:
        logger.error("Failed to write token to DB registry: %s", e)
        return JSONResponse(
            {"error": "Failed to persist token — check gateway logs"},
            status_code=500,
        )

    logger.info(
        "Service token created: token_id=%s agent_id=%s by=%s",
        record.id,
        agent_id,
        examiner,
    )
    return JSONResponse(
        {
            "ok": True,
            "token": raw_token,  # returned exactly once
            "token_id": record.id,
            "token_fingerprint": record.token_fingerprint,
            "agent_id": agent_id,
            "role": token_role,
            "label": label,
            "case_id": record.case_id,
            "created_at": now_iso,
            "expires_at": record.expires_at.isoformat(),
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

    if _TOKEN_REGISTRY is None:
        return JSONResponse(
            {"error": "Token management unavailable: token registry not configured"},
            status_code=503,
        )

    token_id = request.path_params["token_id"]

    try:
        revoked_at = _TOKEN_REGISTRY.revoke_token(token_id, revoked_by=examiner)
    except Exception as e:
        logger.error("Failed to revoke token %s: %s", token_id, e)
        return JSONResponse(
            {"error": "Failed to revoke token — check gateway logs"},
            status_code=500,
        )
    if revoked_at is None:
        return JSONResponse({"error": "Token not found or already revoked"}, status_code=404)

    logger.info("Service token revoked: token_id=%s by=%s", token_id, examiner)
    return JSONResponse({"ok": True, "token_id": token_id, "revoked_at": revoked_at})


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

    if _TOKEN_REGISTRY is None:
        return JSONResponse(
            {"error": "Token management unavailable: token registry not configured"},
            status_code=503,
        )

    token_id = request.path_params["token_id"]

    from sift_gateway.token_gen import generate_service_token

    now_iso = _iso_now()
    new_raw_token = generate_service_token()

    try:
        record = _TOKEN_REGISTRY.rotate_token(
            token_id,
            new_raw_token=new_raw_token,
            rotated_by=examiner,
        )
    except Exception as e:
        logger.error("Failed to rotate token %s: %s", token_id, e)
        return JSONResponse(
            {"error": "Failed to rotate token — check gateway logs"},
            status_code=500,
        )
    if record is None:
        return JSONResponse({"error": "Token not found or already revoked"}, status_code=404)

    logger.info(
        "Service token rotated: old_token_id=%s new_token_id=%s by=%s",
        token_id,
        record.id,
        examiner,
    )
    return JSONResponse(
        {
            "ok": True,
            "revoked_token_id": token_id,
            "token": new_raw_token,  # returned exactly once
            "token_id": record.id,
            "token_fingerprint": record.token_fingerprint,
            "agent_id": record.agent_id,
            "role": record.role,
            "label": record.label,
            "case_id": record.case_id,
            "created_at": now_iso,
            "expires_at": record.expires_at.isoformat(),
        },
        status_code=201,
    )


async def reactivate_token(request: Request) -> JSONResponse:
    """POST /api/tokens/{token_id}/reactivate — reactivate a revoked service token."""
    role_err = _require_examiner_role(request)
    if role_err:
        return role_err

    examiner = _resolve_examiner(request)
    if not examiner:
        return JSONResponse({"error": "Authentication required"}, status_code=401)
    must_err = _must_reset_check(examiner)
    if must_err:
        return must_err

    if _TOKEN_REGISTRY is None:
        return JSONResponse(
            {"error": "Token management unavailable: token registry not configured"},
            status_code=503,
        )

    token_id = request.path_params["token_id"]

    try:
        changed = _TOKEN_REGISTRY.reactivate_token(token_id)
    except Exception as e:
        logger.error("Failed to reactivate token %s: %s", token_id, e)
        return JSONResponse(
            {"error": "Failed to reactivate token — check gateway logs"},
            status_code=500,
        )
    if not changed:
        return JSONResponse({"error": "Token not found or already active"}, status_code=404)

    logger.info("Service token reactivated: token_id=%s by=%s", token_id, examiner)
    return JSONResponse({"ok": True, "token_id": token_id})


# ---------------------------------------------------------------------------
# PR03A — Agent/service principal (Supabase JWT) lifecycle
# ---------------------------------------------------------------------------
#
# These endpoints replace the operator-facing "agent token" target with
# "agent JWT/session" issuance. They call the Gateway-injected supabase_auth
# callbacks; case_dashboard never imports sift_gateway. PR02 token-lifecycle
# endpoints (/api/tokens/*) remain as a legacy compatibility surface.

_PRINCIPAL_KINDS = {"agent", "service"}
_SYSTEM_ROLE_VALUES = {"readonly", "operator", "lead", "owner", "admin"}


def _require_operator(request: Request) -> JSONResponse | None:
    """Deny-by-default operator gate for portal operator APIs (charter invariant).

    A resolved Supabase principal authorizes a portal operator API ONLY when it
    is an operator principal. Agent/service principals presenting a valid JWT are
    rejected with 403 even though they authenticated — principal-truthiness is
    never treated as authorization (C1). On the legacy (no-Supabase) path, the
    examiner/role state set by the middleware governs instead.
    """
    principal = getattr(request.state, "principal", None)
    if isinstance(principal, dict) and principal:
        if principal.get("principal_type") != "operator":
            return JSONResponse({"error": "Operator role required"}, status_code=403)
        return None
    # Legacy path: examiner identity + portal role (examiner/readonly) required.
    examiner = getattr(request.state, "examiner", None)
    if not examiner:
        return JSONResponse({"error": "Authentication required"}, status_code=401)
    return _require_portal_role(request)


def _require_owner_or_admin(request: Request) -> JSONResponse | None:
    """Return 403 unless the resolved operator principal has owner/admin authority.

    Requires an operator principal first (C1), then owner/admin system_role. Falls
    back to examiner-role for the legacy (no-Supabase) path so existing
    deployments keep their behavior.
    """
    principal = getattr(request.state, "principal", None)
    if isinstance(principal, dict) and principal:
        if principal.get("principal_type") != "operator":
            return JSONResponse({"error": "Operator role required"}, status_code=403)
        if principal.get("system_role") not in ("owner", "admin"):
            return JSONResponse(
                {"error": "Owner or admin role required"}, status_code=403
            )
        return None
    # Legacy path: examiner role gates principal management.
    return _require_examiner_role(request)


async def list_principals(request: Request) -> JSONResponse:
    """GET /api/auth/principals — list agent/service app principals (no token material).

    Operator-only (C1): an agent/service principal with a valid Supabase JWT is
    denied (403), not allowed to enumerate the principal roster.
    """
    op_err = _require_operator(request)
    if op_err:
        return op_err

    if _SUPABASE_AUTH is None or not hasattr(_SUPABASE_AUTH, "list_principals"):
        return JSONResponse(
            {"error": "Principal management unavailable: Supabase auth not configured"},
            status_code=503,
        )

    examiner = getattr(request.state, "examiner", None)
    principal = getattr(request.state, "principal", None)
    source_ip = request.client.host if request.client else "unknown"
    creator = principal if isinstance(principal, dict) else {"display_name": examiner}
    try:
        items = await _SUPABASE_AUTH.list_principals(creator, source_ip)
    except Exception as exc:  # noqa: BLE001
        status = _http_status_from_callback_error(exc, default=500)
        return JSONResponse({"error": "Failed to list principals"}, status_code=status)

    # Defensive: never echo token material even if a callback misbehaves.
    safe = []
    for it in items or []:
        if not isinstance(it, dict):
            continue
        safe.append(
            {
                k: v
                for k, v in it.items()
                if k not in ("access_token", "refresh_token", "password")
            }
        )
    return JSONResponse({"principals": safe, "count": len(safe)})


async def create_principal(request: Request) -> JSONResponse:
    """POST /api/auth/principals — create an agent/service Supabase principal.

    Owner/admin operator only. Returns access/refresh token material EXACTLY ONCE;
    it is never stored, persisted, or recoverable afterwards.
    """
    role_err = _require_owner_or_admin(request)
    if role_err:
        return role_err
    if _SUPABASE_AUTH is None:
        return JSONResponse(
            {"error": "Principal management unavailable: Supabase auth not configured"},
            status_code=503,
        )

    creator = getattr(request.state, "principal", None)
    examiner = getattr(request.state, "examiner", None)
    if not (isinstance(creator, dict) and creator) and not examiner:
        return JSONResponse({"error": "Authentication required"}, status_code=401)
    if not (isinstance(creator, dict) and creator):
        creator = {"display_name": examiner}

    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"error": "Invalid JSON"}, status_code=400)

    kind = str(body.get("kind", "")).strip()
    display_name = str(body.get("display_name", "")).strip()
    system_role = str(body.get("system_role", "")).strip() or None
    tool_scopes = body.get("tool_scopes", [])
    case_id = body.get("case_id")
    if case_id is not None:
        case_id = str(case_id).strip() or None

    if kind not in _PRINCIPAL_KINDS:
        return JSONResponse({"error": "kind must be 'agent' or 'service'"}, status_code=400)
    if not display_name or not _TOKEN_LABEL_RE.match(display_name):
        return JSONResponse({"error": "Invalid display_name"}, status_code=400)
    if system_role is not None and system_role not in _SYSTEM_ROLE_VALUES:
        return JSONResponse({"error": "Invalid system_role"}, status_code=400)
    if not isinstance(tool_scopes, list) or not all(
        isinstance(s, str) for s in tool_scopes
    ):
        return JSONResponse({"error": "tool_scopes must be a list of strings"}, status_code=400)
    if kind == "agent" and case_id is None and _ACTIVE_CASES is not None:
        case_id = _active_case_id()
        if not case_id:
            return JSONResponse(
                {"error": "An active DB case is required before issuing an agent principal"},
                status_code=409,
            )

    source_ip = request.client.host if request.client else "unknown"
    try:
        result = await _SUPABASE_AUTH.issue_principal(
            creator,
            kind,
            display_name,
            system_role,
            tool_scopes,
            case_id,
            source_ip,
        )
    except Exception as exc:  # noqa: BLE001 - never leak token material
        status = _http_status_from_callback_error(exc, default=500)
        reason = getattr(exc, "reason", None)
        msg = reason if isinstance(reason, str) and reason else "Failed to create principal"
        return JSONResponse({"error": msg}, status_code=status)

    if not result:
        return JSONResponse({"error": "Failed to create principal"}, status_code=500)

    logger.info(
        "Principal created: type=%s id=%s by=%s",
        result.get("principal_type"),
        result.get("principal_id"),
        result.get("display_name"),
    )
    # Token material returned exactly once; stored nowhere on this side.
    return JSONResponse(
        {
            "ok": True,
            "principal_type": result.get("principal_type"),
            "principal_id": result.get("principal_id"),
            "auth_user_id": result.get("auth_user_id"),
            "display_name": result.get("display_name"),
            "default_case_id": result.get("default_case_id"),
            "access_token": result.get("access_token"),
            "refresh_token": result.get("refresh_token"),
            "expires_at": result.get("expires_at"),
            "token_fingerprint": result.get("fingerprint"),
            "warning": "Copy these tokens now — they cannot be recovered.",
        },
        status_code=201,
    )


async def revoke_principal(request: Request) -> JSONResponse:
    """DELETE /api/auth/principals/{principal_type}/{principal_id} — disable+revoke."""
    role_err = _require_owner_or_admin(request)
    if role_err:
        return role_err
    if _SUPABASE_AUTH is None:
        return JSONResponse(
            {"error": "Principal management unavailable: Supabase auth not configured"},
            status_code=503,
        )

    creator = getattr(request.state, "principal", None)
    examiner = getattr(request.state, "examiner", None)
    if not (isinstance(creator, dict) and creator):
        creator = {"display_name": examiner}

    principal_type = request.path_params.get("principal_type", "")
    principal_id = request.path_params.get("principal_id", "")
    if principal_type not in _PRINCIPAL_KINDS:
        return JSONResponse({"error": "Invalid principal_type"}, status_code=400)
    if not principal_id:
        return JSONResponse({"error": "Missing principal_id"}, status_code=400)

    source_ip = request.client.host if request.client else "unknown"
    try:
        await _SUPABASE_AUTH.revoke_principal(
            creator, principal_type, principal_id, source_ip
        )
    except Exception as exc:  # noqa: BLE001
        status = _http_status_from_callback_error(exc, default=500)
        return JSONResponse({"error": "Failed to revoke principal"}, status_code=status)

    logger.info(
        "Principal revoked: type=%s id=%s by=%s",
        principal_type,
        principal_id,
        examiner or (creator.get("display_name") if isinstance(creator, dict) else None),
    )
    return JSONResponse(
        {"ok": True, "principal_type": principal_type, "principal_id": principal_id}
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


def _write_cli_case_pointer(case_dir: str) -> None:
    """Atomically write the legacy CLI compatibility pointer."""
    sift_dir = Path.home() / ".sift"
    sift_dir.mkdir(parents=True, exist_ok=True)
    active_case_file = sift_dir / "active_case"  # Legacy CLI fallback
    fd, tmp_path = tempfile.mkstemp(dir=str(sift_dir), suffix=".tmp")
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(case_dir)
            f.write("\n")
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp_path, active_case_file)
    except BaseException:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise


def _slugify_case_name(casename: str) -> str:
    """Normalize an already-lowercase portal case name into a path slug."""
    slug = _CASE_SLUG_INVALID_RE.sub("-", casename.strip())
    slug = _CASE_SLUG_HYPHENS_RE.sub("-", slug)
    return slug.strip("-")


# A1-BOOTSTRAP: case path convention is frozen as case-<slug>-<MMDDHHSS> (F-MVP-1).
# The regex accepts the frozen MMDDHHSS suffix (8 digits) and the pre-existing
# YYYYMMDD-HHMM format for backward-compatibility with already-created test cases.
_CASE_ID_RE_STRICT = re.compile(
    r"^case-[a-z][a-z0-9_-]{1,51}-\d{8}$"  # frozen: case-<slug>-<MMDDHHSS>
)
_CASE_ID_RE_LEGACY = re.compile(r"^[a-z][a-z0-9_-]{2,63}$")


def _valid_case_id(case_id: str) -> bool:
    """Accept the frozen MMDDHHSS format or any legacy alphanumeric slug."""
    return bool(_CASE_ID_RE_STRICT.fullmatch(case_id) or _CASE_ID_RE_LEGACY.fullmatch(case_id))


def _make_case_name(slug: str, cases_root: "Path") -> tuple[str, "Path"]:
    """Build a case directory name using the frozen A1-BOOTSTRAP convention.

    Format: case-<slug>-<MMDDHHSS>  (SIFT VM local time, zero-padded).
    If the directory already exists append -NN (01..99) as a collision suffix.

    Returns (case_id, resolved_path).
    """
    # Use local time per spec (SIFT VM clock, not UTC).
    # MMDDHHSS = month(2)+day(2)+hour(2)+second(2) via strftime("%m%d%H%S").
    ts = datetime.now().strftime("%m%d%H%S")
    base_id = f"case-{slug}-{ts}"
    candidate = cases_root / base_id
    if not candidate.exists():
        return base_id, candidate.resolve()
    # Collision suffix -NN (01..99)
    for nn in range(1, 100):
        suffixed = f"{base_id}-{nn:02d}"
        candidate = cases_root / suffixed
        if not candidate.exists():
            return suffixed, candidate.resolve()
    raise ValueError("Too many case-directory collisions (tried 99 suffixes)")


def _load_cases_root() -> Path:
    """Resolve cases root from gateway.yaml case.root or SIFT_CASES_ROOT."""
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
        # No gateway.yaml case.root → fall back to the canonical resolver
        # (SIFT_CASES_ROOT → SIFT_CASES_DIR → ~/cases).
        case_root = str(cases_root())

    expanded = re.sub(
        r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}",
        lambda m: os.environ.get(m.group(1), ""),
        str(case_root),
    )
    return Path(expanded).expanduser().resolve()


async def get_cases(request: Request) -> JSONResponse:
    """GET /portal/api/cases — List DB-visible cases."""
    examiner = _resolve_examiner(request)
    if not examiner:
        return JSONResponse({"error": "Authentication required"}, status_code=401)
    role_err = _require_portal_role(request)
    if role_err:
        return role_err

    if _ACTIVE_CASES is not None:
        try:
            return JSONResponse({"cases": _ACTIVE_CASES.list_cases(_request_principal(request))})
        except Exception as exc:
            return _active_case_error_response(exc)

    try:
        from sift_core.case_ops import case_list_data
        cases_root = _load_cases_root()
        data = case_list_data(cases_root)
        return JSONResponse(data)
    except Exception as e:
        logger.error("Failed to list cases: %s", e)
        return JSONResponse({"error": "Failed to list cases"}, status_code=500)


async def get_case_activate_challenge(request: Request) -> JSONResponse:
    """GET /portal/api/case/activate/challenge — Issue challenge nonce for case activation."""
    if _ACTIVE_CASES is not None and _SUPABASE_AUTH is not None:
        role_err = _require_examiner_role(request)
        if role_err:
            return role_err
        return JSONResponse({"required": False, "authority": "postgres"})

    role_err = _require_examiner_role(request)
    if role_err:
        return role_err

    examiner = _resolve_examiner(request)
    if not examiner:
        return JSONResponse({"error": "No examiner identity"}, status_code=401)

    lockout_msg = _check_commit_lockout(f"activate:{examiner}")
    if lockout_msg:
        return JSONResponse({"error": lockout_msg}, status_code=429)

    err = _must_reset_check(examiner)
    if err:
        return err

    entry = _load_pw_entry(_PASSWORDS_DIR, examiner)
    if not entry:
        return JSONResponse(
            {"error": "No password configured. Run: sift config --setup-password"},
            status_code=403,
        )

    # Purge expired challenges
    now = time.time()
    expired = [
        k for k, v in _activation_challenges.items() if now - v["created_at"] > _ACTIVATION_CHALLENGE_TTL
    ]
    for k in expired:
        del _activation_challenges[k]

    challenge_id = secrets.token_hex(16)
    nonce = secrets.token_hex(32)
    _activation_challenges[challenge_id] = {
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


async def post_case_activate(request: Request) -> JSONResponse:
    """POST /portal/api/case/activate — Activate an existing DB case."""
    examiner = _resolve_examiner(request)
    if not examiner:
        return JSONResponse({"error": "Authentication required"}, status_code=401)
    role_err = _require_examiner_role(request)
    if role_err:
        return role_err

    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"error": "Invalid JSON"}, status_code=400)

    if not isinstance(body, dict):
        return JSONResponse({"error": "Expected JSON object"}, status_code=400)

    case_id = body.get("case_id", "").strip()
    if _ACTIVE_CASES is not None:
        case_id = str(body.get("case_id") or body.get("case_key") or "").strip()
        if not case_id:
            return JSONResponse({"error": "Missing case_id"}, status_code=400)
        try:
            case = _ACTIVE_CASES.set_active_case(case_id, _request_principal(request))
            return JSONResponse({"ok": True, **case.as_dict()})
        except Exception as exc:
            return _active_case_error_response(exc)

    lockout_msg = _check_commit_lockout(f"activate:{examiner}")
    if lockout_msg:
        return JSONResponse({"error": lockout_msg}, status_code=429)

    err = _must_reset_check(examiner)
    if err:
        return err

    challenge_id = body.get("challenge_id", "").strip()
    response_hmac = body.get("response", "").strip()

    if not case_id or not challenge_id or not response_hmac:
        return JSONResponse({"error": "Missing case_id, challenge_id, or response"}, status_code=400)

    if not _valid_case_id(case_id):
        return JSONResponse({"error": "Invalid case_id format"}, status_code=400)

    real_root = _load_cases_root()
    real_requested = (real_root / case_id).resolve()
    if not real_requested.is_relative_to(real_root) or not real_requested.is_dir():
        return JSONResponse({"error": "Case directory not found or invalid"}, status_code=404)

    # Validate challenge
    challenge = _activation_challenges.pop(challenge_id, None)
    if not challenge:
        return JSONResponse({"error": "Invalid or expired challenge"}, status_code=401)

    if challenge.get("bound_ip") != request.client.host:
        return JSONResponse({"error": "Challenge IP mismatch"}, status_code=403)

    now = time.time()
    if now - challenge["created_at"] > _ACTIVATION_CHALLENGE_TTL:
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
        _record_commit_failure(f"activate:{examiner}")
        return JSONResponse({"error": "Incorrect password"}, status_code=401)

    _clear_commit_failures(f"activate:{examiner}")

    # Concurrency serialization using threading.Lock with non-blocking acquire
    acquired = _case_create_lock.acquire(blocking=False)
    if not acquired:
        return JSONResponse({"error": "Another case operation is in progress"}, status_code=409)

    try:
        return JSONResponse(
            {"ok": True, "case_id": case_id, "case_dir": str(real_requested)}
        )

    except Exception as e:
        logger.error("Failed to activate case: %s", e)
        return JSONResponse({"error": "Internal server error during case activation"}, status_code=500)
    finally:
        _case_create_lock.release()


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

    forbidden_fields = {"dir", "directory", "case_dir", "case_id"} & set(body)
    if forbidden_fields:
        return JSONResponse(
            {
                "error": (
                    "Case directory and case_id are computed by the portal; "
                    "submit casename and title only"
                )
            },
            status_code=400,
        )

    casename = body.get("casename", "").strip()
    title = body.get("title", "").strip()
    description = body.get("description", "")
    if not isinstance(description, str):
        return JSONResponse({"error": "description must be a string"}, status_code=400)
    description = description.strip()
    if len(description) > 10_000:
        return JSONResponse({"error": "description exceeds 10000 characters"}, status_code=400)

    if not casename or not title:
        return JSONResponse({"error": "Missing required fields"}, status_code=400)

    if casename != casename.lower():
        return JSONResponse({"error": "casename must be lowercase"}, status_code=400)

    slug = _slugify_case_name(casename)
    real_root = _load_cases_root()

    # R5: slug must not contain path separators or traversal sequences.
    if "/" in slug or "\\" in slug or ".." in slug:
        return JSONResponse({"error": "Directory must be under case root"}, status_code=400)

    # A1-BOOTSTRAP: use frozen convention case-<slug>-<MMDDHHSS> with -NN collision suffix.
    try:
        case_id, real_requested = _make_case_name(slug, real_root)
    except ValueError as exc:
        return JSONResponse({"error": str(exc)}, status_code=409)

    if not _valid_case_id(case_id):
        return JSONResponse({"error": "Invalid case_id format"}, status_code=400)

    if not real_requested.is_relative_to(real_root):
        return JSONResponse({"error": "Directory must be under case root"}, status_code=400)

    # Concurrency serialization using threading.Lock with non-blocking acquire
    acquired = _case_create_lock.acquire(blocking=False)
    if not acquired:
        return JSONResponse({"error": "Another case creation is in progress"}, status_code=409)

    try:
        # Re-check under lock (race between _make_case_name and mkdir)
        if real_requested.exists():
            return JSONResponse({"error": "Case directory already exists"}, status_code=409)

        # Create directories
        real_requested.mkdir(parents=True)
        for subdir in ("audit", "evidence", "extractions", "reports", "agent"):
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
            "created_at": ts.isoformat(),
        }
        if description:
            case_meta["description"] = description

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
            ("todos.json", "[]"),
            ("iocs.json", "[]"),
        ]:
            path = real_requested / fname
            with open(path, "w", encoding="utf-8") as f:
                f.write(content)
                f.flush()
                os.fsync(f.fileno())

        # Evidence chain: write evidence-manifest.json (v0) + evidence-ledger.jsonl
        init_evidence_chain(real_requested)
        case_approvals_path(real_requested).touch(exist_ok=True)
        runtime_acl = _configure_agent_runtime_case_acl(real_requested)
        if runtime_acl.get("status") not in {"configured", "skipped"}:
            logger.warning("case create: runtime ACL setup incomplete: %s", runtime_acl)

        db_case = None
        if _ACTIVE_CASES is not None:
            try:
                db_case = _ACTIVE_CASES.create_case(
                    {
                        "case_key": case_id,
                        "title": title,
                        "description": description,
                        "artifact_path": str(real_requested),
                        "activate": bool(body.get("activate", True)),
                    },
                    _request_principal(request),
                )
            except Exception as exc:
                return _active_case_error_response(exc)

        if db_case is not None:
            return JSONResponse({"ok": True, **db_case.as_dict()})
        return JSONResponse({"ok": True, "case_id": case_id, "case_dir": str(real_requested)})

    except Exception as e:
        logger.error("Failed to create case: %s", e)
        return JSONResponse({"error": "Internal server error during case creation"}, status_code=500)
    finally:
        _case_create_lock.release()


# --- Reports Endpoints ---

_PENDING_REPORTS: dict[str, dict] = {}
_IN_FLIGHT_GENERATIONS = set()
_GENERATION_LOCK = threading.Lock()


def _serialize_to_markdown(report: dict) -> str:
    """Serialize structured report dict into a clean, comprehensive markdown format."""
    meta = report.get("report_data", {}).get("metadata", {}) or {}
    profile = report.get("profile", "full").upper()
    generated_at = report.get("generated_at", "")
    examiner = report.get("examiner", "Unknown")
    case_name = meta.get("name", "Unknown Case")
    case_id = meta.get("case_id", "Unknown ID")

    md = []
    md.append(f"# Forensic Incident Report: {case_name}")
    md.append("")
    md.append("## Report Metadata")
    md.append(f"- **Case ID**: {case_id}")
    md.append(f"- **Report Profile**: {profile}")
    md.append(f"- **Generated At**: {generated_at}")
    md.append(f"- **Examiner**: {examiner}")
    md.append("")

    # Integrity Warnings
    if "integrity_warning" in report:
        md.append("> [!CAUTION]")
        md.append(f"> **Evidence Integrity Warning**: {report['integrity_warning']}")
        md.append("")
    elif "evidence_chain_warning" in report:
        md.append("> [!WARNING]")
        md.append(f"> **Evidence Chain Warning**: {report['evidence_chain_warning']}")
        md.append("")

    # Render sections based on their order in report
    sections = report.get("sections", []) or []
    report_data = report.get("report_data", {}) or {}
    zg = report.get("zeltser_guidance", {}) or {}

    for sec in sections:
        name = sec.get("name", "Section")
        data_key = sec.get("data_key")

        md.append(f"## {name}")
        md.append("")

        if not data_key:
            # Narrative/guidance section
            guidance = zg.get(name, {})
            if isinstance(guidance, dict):
                instr = guidance.get("instructions", [])
                if instr:
                    md.append("### Guidance & Instructions")
                    for ins in instr:
                        md.append(f"- {ins}")
                    md.append("")
            # Placeholders for human input
            matching_hr = [hr for hr in report.get("human_review_required", []) or [] if hr.get("section") == name]
            if matching_hr:
                md.append("> [!IMPORTANT]")
                md.append(f"> **Human Curation Required**: {matching_hr[0].get('reason')}")
                md.append(f"> {matching_hr[0].get('prompt')}")
                md.append("")
            else:
                md.append(f"[Draft Section: Write narrative for {name} here]")
                md.append("")
        else:
            # Data section
            data = report_data.get(data_key)
            if data is None:
                # Fallback check for count suffix keys
                if f"{data_key}_count" in report_data:
                    md.append(f"Total count of {data_key}: **{report_data[f'{data_key}_count']}**")
                    md.append("")
                else:
                    md.append("*No data available for this section.*")
                    md.append("")
                continue

            if data_key == "summary":
                md.append("| Metric | Count |")
                md.append("|---|---|")
                for k, v in data.items():
                    if isinstance(v, (int, float)):
                        name_pretty = k.replace("_", " ").title()
                        md.append(f"| {name_pretty} | {v} |")
                md.append("")
            elif data_key == "findings":
                if not data:
                    md.append("*No approved findings in this report.*")
                    md.append("")
                else:
                    for f in data:
                        fid = f.get("id", "N/A")
                        ftitle = f.get("title", "Untitled")
                        fconfidence = f.get("confidence", "N/A")
                        ftype = f.get("type", "N/A")
                        fhost = f.get("host", "N/A")
                        facc = f.get("affected_account", "N/A")
                        fts = f.get("event_timestamp") or f.get("timestamp", "N/A")

                        md.append(f"### Finding {fid}: {ftitle}")
                        md.append(f"- **Type**: {ftype}")
                        md.append(f"- **Confidence**: {fconfidence}")
                        md.append(f"- **Host**: {fhost}")
                        md.append(f"- **Affected Account**: {facc}")
                        md.append(f"- **Event Timestamp**: {fts}")
                        if f.get("tags"):
                            md.append(f"- **Tags**: {', '.join(f.get('tags'))}")
                        md.append("")

                        if f.get("observation"):
                            md.append("#### Observation")
                            md.append(str(f["observation"]))
                            md.append("")
                        if f.get("interpretation"):
                            md.append("#### Interpretation")
                            md.append(str(f["interpretation"]))
                            md.append("")
            elif data_key == "timeline":
                if not data:
                    md.append("*No timeline events included.*")
                    md.append("")
                else:
                    md.append("| Timestamp | Host | Type | Description |")
                    md.append("|---|---|---|---|")
                    for t in data:
                        ts = t.get("timestamp", "N/A")
                        host = t.get("host", "N/A")
                        ttype = t.get("type", "N/A")
                        desc = t.get("description", "No description")
                        md.append(f"| {ts} | {host} | {ttype} | {desc} |")
                    md.append("")
            elif data_key == "iocs":
                if not data:
                    md.append("*No indicators of compromise.*")
                    md.append("")
                else:
                    md.append("| Value | Type | Category | Host | Source Findings |")
                    md.append("|---|---|---|---|---|")
                    rows: list[dict] = []
                    if isinstance(data, dict):
                        for ioc_type, items in data.items():
                            if not isinstance(items, list):
                                continue
                            for it in items:
                                if isinstance(it, dict):
                                    rows.append({**it, "type": it.get("type") or ioc_type})
                                elif isinstance(it, str):
                                    rows.append({"value": it, "type": ioc_type})
                    elif isinstance(data, list):
                        for it in data:
                            if isinstance(it, dict):
                                rows.append(it)
                            elif isinstance(it, str):
                                rows.append({"value": it})
                    for i in rows:
                        val = i.get("value", "N/A")
                        itype = i.get("type", "N/A")
                        cat = i.get("category", "N/A")
                        host = i.get("host", "N/A")
                        src = ", ".join(i.get("source_findings", []))
                        md.append(f"| {val} | {itype} | {cat} | {host} | {src} |")
                    md.append("")
            elif data_key == "mitre_mapping":
                if not data:
                    md.append("*No MITRE ATT&CK mapping.*")
                    md.append("")
                else:
                    md.append("| Technique ID | Technique Name | Findings |")
                    md.append("|---|---|---|")
                    for tech_id, tech_info in data.items():
                        tname = tech_info.get("name", "Unknown Technique")
                        tfindings = ", ".join(tech_info.get("findings", []))
                        md.append(f"| {tech_id} | {tname} | {tfindings} |")
                    md.append("")
            elif data_key == "evidence":
                if not data:
                    md.append("*No evidence files registered.*")
                    md.append("")
                else:
                    md.append("| Path | Size (Bytes) | Hash | Status |")
                    md.append("|---|---|---|---|")
                    for ev in data:
                        path = ev.get("path", "N/A")
                        sz = ev.get("size_bytes", 0)
                        hsh = ev.get("sha256", "N/A")
                        stat = ev.get("status", "N/A")
                        md.append(f"| {path} | {sz} | `{hsh}` | {stat} |")
                    md.append("")
            elif data_key == "todos":
                if not data:
                    md.append("*No open TODOs.*")
                    md.append("")
                else:
                    for t in data:
                        title = t.get("title", "Untitled")
                        desc = t.get("description", "No description")
                        prio = t.get("priority", "N/A")
                        ex = t.get("examiner", "N/A")
                        md.append(f"- **{title}** (Priority: {prio}, Assigned: {ex})")
                        md.append(f"  {desc}")
                    md.append("")
            else:
                md.append(f"```json\n{json.dumps(data, indent=2)}\n```")
                md.append("")

    # Custody / provenance appendix (F-MVP-4) — rendered on every report as
    # trailing verification material. Sourced from the top-level appendix the
    # core generator built; carries hashes, provenance/audit ids, and seal
    # status only — never absolute paths.
    appendix = report.get("custody_appendix") or {}
    if appendix:
        md.append("## Appendix: Custody & Provenance")
        md.append("")
        md.append(appendix.get("verification_note", ""))
        md.append("")
        if appendix.get("authorized_by_reauth_event"):
            md.append(
                f"- **Authorized by re-auth event**: `{appendix['authorized_by_reauth_event']}`"
            )
            md.append("")
        seal = appendix.get("evidence_seal", {}) or {}
        md.append("### Evidence Seal & Hash-Chain Proof")
        md.append("| Field | Value |")
        md.append("|---|---|")
        md.append(f"| Seal Status | {seal.get('seal_status', 'N/A')} |")
        md.append(f"| Manifest Version | {seal.get('manifest_version', 0)} |")
        md.append(f"| Manifest Hash | `{seal.get('manifest_hash') or 'N/A'}` |")
        md.append(f"| Chain Head Hash | `{seal.get('chain_head_hash') or 'N/A'}` |")
        md.append(f"| Ledger Tip Hash | `{seal.get('ledger_tip_hash') or 'N/A'}` |")
        md.append(f"| Active Evidence Count | {seal.get('active_count', 0)} |")
        md.append("")
        fp = appendix.get("finding_provenance", []) or []
        md.append("### Finding Provenance")
        if not fp:
            md.append("*No approved findings.*")
            md.append("")
        else:
            md.append("| Finding ID | Approval Hash | Approved By | Provenance / Audit Refs |")
            md.append("|---|---|---|---|")
            for entry in fp:
                fid = entry.get("id", "N/A")
                chash = entry.get("content_hash") or "N/A"
                by = entry.get("approved_by") or "N/A"
                refs = ", ".join(entry.get("provenance_refs", [])) or "—"
                md.append(f"| {fid} | `{chash}` | {by} | {refs} |")
            md.append("")
        custody = appendix.get("custody")
        if custody:
            md.append("### Custody Ledger Summary")
            md.append(f"```json\n{json.dumps(custody, indent=2, default=str)}\n```")
            md.append("")

    return "\n".join(md)


def _report_eligibility() -> dict | None:
    """Approved-only report eligibility from DB authority (_REPORT_DB).

    Returns a dict {eligible, approved_findings, total_findings, reason?} or None
    when no DB report service is wired. Report GENERATION internals belong to
    BATCH-J1; E1 only surfaces eligibility/approval visibility.
    """
    if _REPORT_DB is None:
        return None
    case_id = _active_case_id()
    if not case_id:
        return None
    fn = getattr(_REPORT_DB, "report_eligibility", None)
    if not callable(fn):
        return None
    try:
        elig = fn(case_id)
    except Exception as exc:
        logger.warning("DB report_eligibility failed: %s", exc)
        return None
    return elig if isinstance(elig, dict) else None


def _db_custody_summary() -> dict | None:
    """Sanitized custody summary for the report appendix (F-MVP-4).

    Folds the C1 evidence gate status (seal/version/head hash) and, when
    available, the custody-events summary into one dict for the provenance
    appendix. Returns None when no DB evidence authority is wired (file-backed
    deployments rely on the manifest the core generator already reads). Never
    contains absolute case/evidence/mount paths.
    """
    db_status = _db_evidence_chain_status()
    if db_status is None:
        return None
    summary: dict = {
        "seal_status": db_status.get("seal_status"),
        "manifest_version": db_status.get("manifest_version"),
        "head_hash": db_status.get("head_hash"),
        "active_count": db_status.get("active_count"),
        "issues": db_status.get("issues", []),
        "last_verified_at": db_status.get("hmac_last_verified_at"),
    }
    if _EVIDENCE_DB is not None:
        events_fn = getattr(_EVIDENCE_DB, "custody_events", None)
        if callable(events_fn):
            try:
                summary["events"] = events_fn(_active_case_id())
            except Exception as exc:
                logger.warning("DB custody_events for report appendix failed: %s", exc)
    return summary


def _report_reauth(request: Request, examiner: str, action: str, body: dict) -> tuple[JSONResponse | None, str | None]:
    """Verify operator re-auth for a report inclusion/export action (F-MVP-4).

    Re-uses the evidence HMAC challenge/response so report inclusion and export
    are gated by the same password/HMAC re-auth as the other sensitive human
    actions (AGENTS.md security invariant), and records a re-auth audit event
    (consistent with C1/E1). Enforced only when DB evidence authority is wired —
    the same condition under which seal/ignore/retire require re-auth — so
    file-backed deployments and E1's report-only fakes are unaffected.

    Returns (error_response | None, reauth_audit_event_id | None).
    """
    if _EVIDENCE_DB is None:
        return None, None

    challenge_id = str(body.get("challenge_id", ""))
    response_hmac = str(body.get("response", ""))
    if not challenge_id or not response_hmac:
        return (
            JSONResponse(
                {"error": "Re-auth required: report inclusion/export needs password confirmation."},
                status_code=403,
            ),
            None,
        )
    err_msg, _ = _verify_evidence_hmac(
        examiner, challenge_id, response_hmac, request.client.host
    )
    if err_msg:
        return JSONResponse({"error": err_msg}, status_code=401), None

    reauth_id = _record_reauth_event(request, examiner, action)
    if not reauth_id:
        return (
            JSONResponse(
                {"error": "Re-auth audit event required for report inclusion/export."},
                status_code=403,
            ),
            None,
        )
    return None, reauth_id


def _record_report_metadata(
    *,
    report_id: str,
    profile: str,
    examiner: str,
    created_at: str,
    reauth_audit_event_id: str | None,
    appendix: dict,
    export: bool = False,
) -> None:
    """Persist report metadata to DB authority via the E1 report_service seam.

    Optional and defensive: when no DB report service (or no recorder method) is
    wired, this is a no-op and the file artifact remains the only record. The
    metadata is non-authoritative provenance — seal status + hashes + the re-auth
    event id — and never carries absolute paths or report body content.
    """
    if _REPORT_DB is None:
        return
    recorder = getattr(_REPORT_DB, "record_report", None)
    if not callable(recorder):
        return
    case_id = _active_case_id()
    if not case_id:
        return
    seal = (appendix or {}).get("evidence_seal", {}) or {}
    # Prefer the DB custody authority's seal status when folded into the
    # appendix; the appendix's evidence_seal block can be the file-backed view.
    custody = (appendix or {}).get("custody") or {}
    metadata = {
        "report_id": report_id,
        "profile": profile,
        "examiner": examiner,
        "created_at": created_at,
        "reauth_audit_event_id": reauth_audit_event_id,
        "seal_status": custody.get("seal_status") or seal.get("seal_status"),
        "manifest_version": custody.get("manifest_version", seal.get("manifest_version")),
        "manifest_hash": seal.get("manifest_hash"),
        "chain_head_hash": custody.get("head_hash") or seal.get("chain_head_hash"),
        "exported": export,
    }
    try:
        recorder(case_id=case_id, **metadata)
    except Exception as exc:
        logger.warning("DB record_report failed: %s", exc)


async def get_report_challenge(request: Request) -> JSONResponse:
    """Issue a re-auth challenge for report generation/export (F-MVP-4).

    Thin alias over the evidence-chain challenge so the portal can confirm the
    operator's password before generating or exporting a report.
    """
    return await get_evidence_chain_challenge(request)


async def get_reports(request: Request) -> JSONResponse:
    examiner = _resolve_examiner(request)
    if not examiner:
        return JSONResponse({"error": "Authentication required"}, status_code=401)
    role_err = _require_examiner_role(request)
    if role_err:
        return role_err

    # DB-authority path: report metadata list from Postgres.
    if _REPORT_DB is not None:
        lister = getattr(_REPORT_DB, "list_reports", None)
        case_id = _active_case_id()
        if callable(lister) and case_id:
            try:
                rows = lister(case_id) or []
            except Exception as exc:
                return _active_case_error_response(exc, default=500)
            return JSONResponse(rows if isinstance(rows, list) else [])

    case_dir = _resolve_case_dir()
    if not case_dir:
        return _no_case_response()

    reports_dir = case_dir / "reports"
    if not reports_dir.exists():
        return JSONResponse([])

    reports = []
    for p in sorted(reports_dir.iterdir()):
        if p.is_file() and p.suffix == ".json":
            try:
                stem = p.stem
                uuid.UUID(stem)
                data = json.loads(p.read_text(encoding="utf-8"))
                reports.append({
                    "id": data.get("id"),
                    "profile": data.get("profile"),
                    "created_at": data.get("created_at"),
                    "examiner": data.get("examiner"),
                })
            except (ValueError, json.JSONDecodeError, OSError):
                continue
    reports.sort(key=lambda x: x.get("created_at", ""), reverse=True)
    return JSONResponse(reports)


async def generate_report_route(request: Request) -> JSONResponse:
    examiner = _resolve_examiner(request)
    if not examiner:
        return JSONResponse({"error": "Authentication required"}, status_code=401)
    role_err = _require_examiner_role(request)
    if role_err:
        return role_err

    # Approved-only eligibility gate (DB authority). A report may only be
    # generated when there is at least one approved finding; this keeps reports to
    # human-approved supporting data. Falls through when no DB report service is
    # wired (eligibility then enforced by the file-backed generator).
    elig = _report_eligibility()
    if elig is not None and not elig.get("eligible", False):
        return JSONResponse(
            {
                "error": "No approved findings — report generation requires at "
                "least one approved finding.",
                "eligibility": elig,
            },
            status_code=409,
        )

    case_dir = _resolve_case_dir()
    if not case_dir:
        return _no_case_response()
    case_id = case_dir.name

    with _GENERATION_LOCK:
        if case_id in _IN_FLIGHT_GENERATIONS:
            return JSONResponse({"error": "Too many attempts. A report generation is already in progress for this case."}, status_code=429)
        _IN_FLIGHT_GENERATIONS.add(case_id)

    try:
        try:
            body = await request.json()
        except json.JSONDecodeError:
            return JSONResponse({"error": "Invalid JSON body"}, status_code=400)

        profile = body.get("profile", "full")
        from sift_core.report_profiles import PROFILES
        if profile not in PROFILES:
            return JSONResponse({
                "error": f"Unknown profile: {profile}. Valid profiles: {', '.join(sorted(PROFILES))}"
            }, status_code=400)

        finding_ids = body.get("finding_ids")
        start_date = body.get("start_date", "")
        end_date = body.get("end_date", "")

        # Operator re-auth for report inclusion (F-MVP-4). Enforced only when DB
        # evidence authority is wired; yields a re-auth audit event id stamped
        # into the report's custody appendix.
        reauth_err, reauth_id = _report_reauth(
            request, examiner, "report_generate", body
        )
        if reauth_err is not None:
            return reauth_err

        # Sanitized custody summary for the provenance appendix (DB authority).
        custody = _db_custody_summary()

        # BATCH-K2: in DB-active mode, report inclusion reads approved findings/
        # timeline from Postgres authority, never the case JSON. A missing/empty
        # set still yields a (gated) report with no findings rather than reading
        # tamperable files.
        investigation_inputs = None
        if _db_investigation_active():
            getter = getattr(_INVESTIGATION_DB, "report_inputs", None)
            if callable(getter):
                try:
                    investigation_inputs = getter(_active_case_id())
                except Exception as exc:
                    logger.warning("DB report inputs unavailable: %s", exc)
                    investigation_inputs = {"findings": [], "timeline": [], "iocs": []}

        from sift_core.reporting import generate_report_data
        result = generate_report_data(
            profile_name=profile,
            case_dir=case_dir,
            finding_ids=finding_ids,
            start_date=start_date,
            end_date=end_date,
            custody=custody,
            reauth_audit_event_id=reauth_id,
            investigation_inputs=investigation_inputs,
        )

        if isinstance(result, dict) and "error" in result:
             logger.error("Report generation internal error: %s", result["error"])
             return JSONResponse({"error": "Report generation failed. Check the case status."}, status_code=500)

        report_id = str(uuid.uuid4())
        result["id"] = report_id
        result["examiner"] = examiner
        result["created_at"] = datetime.now(timezone.utc).isoformat()

        _PENDING_REPORTS[report_id] = result

        # Persist report metadata to DB authority so list_reports reflects it
        # (F-MVP-4). The report file is an exported artifact, not authority; the
        # DB row is. Optional seam — bound live by the dedicated binding batch
        # (B-MVP-5); a missing recorder is a no-op here.
        _record_report_metadata(
            report_id=report_id,
            profile=profile,
            examiner=examiner,
            created_at=result["created_at"],
            reauth_audit_event_id=reauth_id,
            appendix=result.get("custody_appendix", {}),
        )

        response_payload = {
            "id": report_id,
            "profile": profile,
            "report_data": result.get("report_data"),
            "sections": result.get("sections"),
            "guidance": result.get("writing_guidance"),
            "evidence_chain": result.get("evidence_chain"),
            "custody_appendix": result.get("custody_appendix"),
            "integrity_warning": result.get("integrity_warning"),
            "evidence_chain_warning": result.get("evidence_chain_warning"),
            "verification_alerts": result.get("verification_alerts"),
        }
        return JSONResponse(response_payload)

    except Exception as e:
        logger.exception("Failed to generate report for case %s: %s", case_id, e)
        return JSONResponse({"error": "Report generation failed. Check the case status."}, status_code=500)
    finally:
        with _GENERATION_LOCK:
            _IN_FLIGHT_GENERATIONS.discard(case_id)


async def save_report_route(request: Request) -> JSONResponse:
    examiner = _resolve_examiner(request)
    if not examiner:
        return JSONResponse({"error": "Authentication required"}, status_code=401)
    role_err = _require_examiner_role(request)
    if role_err:
        return role_err

    case_dir = _resolve_case_dir()
    if not case_dir:
        return _no_case_response()

    report_id = request.path_params["id"]
    try:
        uuid.UUID(report_id)
    except ValueError:
        return JSONResponse({"error": "Invalid report ID format. Must be a UUID."}, status_code=400)

    if report_id not in _PENDING_REPORTS:
        return JSONResponse({"error": "Report draft not found or expired"}, status_code=404)

    report_draft = _PENDING_REPORTS[report_id]
    reports_dir = case_dir / "reports"
    reports_dir.mkdir(exist_ok=True)

    from sift_core.case_io import _protected_write
    try:
        report_path = reports_dir / f"{report_id}.json"
        _protected_write(report_path, json.dumps(report_draft, indent=2, default=str))
        logger.info("Saved report draft %s to case %s", report_id, case_dir.name)

        return JSONResponse({
            "status": "saved",
            "id": report_id,
            "filename": f"{report_id}.json",
            "profile": report_draft.get("profile"),
        })
    except Exception as e:
        logger.exception("Failed to save report %s: %s", report_id, e)
        return JSONResponse({"error": "Failed to save report. Check console/logs."}, status_code=500)


async def get_report_by_id(request: Request) -> JSONResponse:
    examiner = _resolve_examiner(request)
    if not examiner:
        return JSONResponse({"error": "Authentication required"}, status_code=401)
    role_err = _require_examiner_role(request)
    if role_err:
        return role_err

    case_dir = _resolve_case_dir()
    if not case_dir:
        return _no_case_response()

    report_id = request.path_params["id"]
    try:
        uuid.UUID(report_id)
    except ValueError:
        return JSONResponse({"error": "Invalid report ID format. Must be a UUID."}, status_code=400)

    reports_dir = case_dir / "reports"
    report_path = reports_dir / f"{report_id}.json"

    if not report_path.is_relative_to(reports_dir) or not report_path.exists():
        if report_id in _PENDING_REPORTS:
            return JSONResponse(_PENDING_REPORTS[report_id])
        return JSONResponse({"error": f"Report {report_id} not found"}, status_code=404)

    try:
        data = json.loads(report_path.read_text(encoding="utf-8"))
        return JSONResponse(data)
    except Exception as e:
        logger.exception("Failed to load report %s: %s", report_id, e)
        return JSONResponse({"error": "Failed to load report."}, status_code=500)


async def download_report(request: Request) -> Response:
    examiner = _resolve_examiner(request)
    if not examiner:
        return Response("Authentication required", status_code=401)
    if getattr(request.state, "role", None) != "examiner":
        return Response("Examiner role required", status_code=403)

    case_dir = _resolve_case_dir()
    if not case_dir:
        return Response("No active case.", status_code=404)

    report_id = request.path_params["id"]
    try:
        uuid.UUID(report_id)
    except ValueError:
        return Response("Invalid report ID format.", status_code=400)

    reports_dir = case_dir / "reports"
    report_path = reports_dir / f"{report_id}.json"

    report_data = None
    if report_path.is_relative_to(reports_dir) and report_path.exists():
        try:
            report_data = json.loads(report_path.read_text(encoding="utf-8"))
        except Exception:
            pass

    if not report_data and report_id in _PENDING_REPORTS:
        report_data = _PENDING_REPORTS[report_id]

    if not report_data:
        return Response("Report not found.", status_code=404)

    try:
        markdown_content = _serialize_to_markdown(report_data)
        profile = report_data.get("profile", "report")
        filename = f"report_{profile}_{report_id[:8]}.md"

        # Record the export as non-authoritative provenance (F-MVP-4): the
        # exported bundle is an artifact, the DB row is the record. Best-effort,
        # only when the report_service seam exposes a recorder.
        _record_report_metadata(
            report_id=report_id,
            profile=profile,
            examiner=examiner,
            created_at=report_data.get("created_at", ""),
            reauth_audit_event_id=report_data.get("reauth_audit_event_id"),
            appendix=report_data.get("custody_appendix", {}),
            export=True,
        )

        headers = {
            "Content-Disposition": f'attachment; filename="{filename}"',
            "Content-Type": "text/markdown; charset=utf-8",
        }
        return Response(markdown_content, headers=headers)
    except Exception as e:
        logger.exception("Failed to serialize/download report: %s", e)
        return Response("Failed to generate markdown report.", status_code=500)


# ---------------------------------------------------------------------------
# Portal state aggregation + job status (BATCH-E1)
# ---------------------------------------------------------------------------


async def get_job_status(request: Request) -> JSONResponse:
    """Return sanitized status for one job via the D2 Gateway job adapter.

    The adapter (sift_gateway.jobs.JobService) returns only the agent-safe
    allow-list — never spec_internal, worker_id, lease internals, local paths, or
    raw DB errors — and enforces case membership for the principal. When no job
    service is wired, returns 503 so the portal can fall back to legacy status.
    """
    examiner = _resolve_examiner(request)
    if not examiner:
        return JSONResponse({"error": "Authentication required"}, status_code=401)
    role_err = _require_portal_role(request)
    if role_err:
        return role_err

    if _JOB_SERVICE is None:
        return JSONResponse({"error": "Job service not wired"}, status_code=503)

    job_id = request.path_params["job_id"]
    try:
        status = _JOB_SERVICE.job_status_public(job_id, _request_principal(request))
    except Exception as exc:
        return _active_case_error_response(exc, default=500)
    return JSONResponse(status if isinstance(status, dict) else {})


async def get_portal_state(request: Request) -> JSONResponse:
    """Aggregate operator-facing status the portal needs to render clearly:
    evidence seal status, custody summary, add-on status, and report eligibility.

    Read-only. Sourced from DB authority when wired; each block degrades to null
    when its service is absent so the frontend can show "not wired" rather than
    failing. Never surfaces absolute case/evidence/mount paths or secrets.
    """
    examiner = _resolve_examiner(request)
    if not examiner:
        return JSONResponse({"error": "Authentication required"}, status_code=401)
    role_err = _require_portal_role(request)
    if role_err:
        return role_err

    state: dict = {
        "authority": "db",
        "evidence": None,
        "custody": None,
        "addons": None,
        "report_eligibility": None,
    }

    # Evidence seal/custody status (DB custody authority only). Degrades to a
    # graceful no_case payload on a fresh install — never reads a file.
    db_status = _evidence_chain_status()
    state["evidence"] = {
        "seal_status": db_status.get("seal_status"),
        "manifest_version": db_status.get("manifest_version"),
        "active_count": db_status.get("active_count"),
        "issues": db_status.get("issues", []),
        "hmac_verify_needed": db_status.get("hmac_verify_needed"),
    }
    if _EVIDENCE_DB is not None:
        events_fn = getattr(_EVIDENCE_DB, "custody_events", None)
        if callable(events_fn):
            try:
                state["custody"] = events_fn(_active_case_id())
            except Exception as exc:
                logger.warning("DB custody_events failed: %s", exc)

    # Add-on status — surfaced read-only from the backend registry when wired.
    if _EVIDENCE_DB is not None or _INVESTIGATION_DB is not None:
        addons_fn = getattr(_REPORT_DB, "addon_status", None)
        if callable(addons_fn):
            try:
                state["addons"] = addons_fn(_active_case_id())
            except Exception as exc:
                logger.warning("DB addon_status failed: %s", exc)

    state["report_eligibility"] = _report_eligibility()
    return JSONResponse(state)


def _dashboard_api_routes() -> list[Route]:
    """API routes shared by v1 and v2 dashboard apps."""
    return [
        Route("/api/portal/state", get_portal_state, methods=["GET"]),
        Route("/api/jobs/{job_id}", get_job_status, methods=["GET"]),
        Route("/api/reports", get_reports, methods=["GET"]),
        Route("/api/reports/challenge", get_report_challenge, methods=["GET"]),
        Route("/api/reports/generate", generate_report_route, methods=["POST"]),
        Route("/api/reports/{id}/save", save_report_route, methods=["POST"]),
        Route("/api/reports/{id}", get_report_by_id, methods=["GET"]),
        Route("/api/reports/{id}/download", download_report, methods=["GET"]),
        Route("/api/findings", get_findings, methods=["GET"]),
        Route("/api/findings/{id}", get_finding_by_id, methods=["GET"]),
        Route("/api/timeline", get_timeline, methods=["GET"]),
        Route("/api/evidence", get_evidence, methods=["GET"]),
        Route("/api/audit/{finding_id}", get_audit_for_finding, methods=["GET"]),
        Route("/api/delta", get_delta, methods=["GET"]),
        Route("/api/delta", post_delta, methods=["POST"]),
        Route("/api/delta/{id}", delete_delta_item, methods=["DELETE"]),
        Route("/api/case", get_case, methods=["GET"]),
        Route("/api/case/metadata", post_case_metadata, methods=["POST"]),
        Route("/api/todos", get_todos, methods=["GET"]),
        Route("/api/todos", post_todo, methods=["POST"]),
        Route("/api/todos/{todo_id}", patch_todo, methods=["PATCH"]),
        Route("/api/todos/{todo_id}", delete_todo, methods=["DELETE"]),
        Route("/api/iocs", get_iocs, methods=["GET"]),
        Route("/api/summary", get_summary, methods=["GET"]),
        Route("/api/evidence/{path:path}/verify", verify_evidence, methods=["POST"]),
        Route("/api/commit/challenge", get_commit_challenge, methods=["GET"]),
        Route("/api/commit", post_commit, methods=["POST"]),
        # Phase 16a: evidence chain intake
        Route("/api/evidence/chain/status", get_evidence_chain_status, methods=["GET"]),
        Route("/api/evidence/chain/rescan", post_evidence_chain_rescan, methods=["POST"]),
        Route("/api/evidence/chain/challenge", get_evidence_chain_challenge, methods=["GET"]),
        Route("/api/evidence/chain/seal", post_evidence_chain_seal, methods=["POST"]),
        Route("/api/evidence/chain/ignore", post_evidence_chain_ignore, methods=["POST"]),
        Route("/api/evidence/chain/delete", post_evidence_chain_delete, methods=["POST"]),
        Route("/api/evidence/chain/retire", post_evidence_chain_retire, methods=["POST"]),
        Route("/api/evidence/chain/verify-hmac", post_evidence_chain_verify_hmac, methods=["POST"]),
        Route("/api/evidence/chain/anchor", post_evidence_chain_anchor, methods=["POST"]),
        Route("/api/evidence/chain/proof-export", post_evidence_chain_proof_export, methods=["POST"]),
        # Approach C: response-guard override
        Route("/api/response-guard/status", get_response_guard_status, methods=["GET"]),
        Route("/api/response-guard/override", post_response_guard_override, methods=["POST"]),
        Route("/api/response-guard/override/cancel", post_response_guard_override_cancel, methods=["POST"]),
        # Phase 12d: auth endpoints
        Route("/api/auth/setup-required", get_auth_setup_required, methods=["GET"]),
        Route("/api/auth/setup", post_auth_setup, methods=["POST"]),
        Route("/api/auth/challenge", get_auth_challenge, methods=["GET"]),
        Route("/api/auth/login", post_auth_login, methods=["POST"]),
        Route("/api/auth/reset-password", post_auth_reset_password, methods=["POST"]),
        # A1-BOOTSTRAP: installer forced-reset endpoint (Supabase path only)
        Route("/api/auth/forced-reset", post_supabase_forced_reset, methods=["POST"]),
        Route("/api/auth/logout", post_auth_logout, methods=["POST"]),
        Route("/api/auth/refresh", post_supabase_refresh, methods=["POST"]),
        Route("/api/auth/me", get_auth_me, methods=["GET"]),
        # PR03A — agent/service Supabase principal lifecycle
        Route("/api/auth/principals", list_principals, methods=["GET"]),
        Route("/api/auth/principals", create_principal, methods=["POST"]),
        Route(
            "/api/auth/principals/{principal_type}/{principal_id}",
            revoke_principal,
            methods=["DELETE"],
        ),
        # Phase 13f: service-token lifecycle
        Route("/api/tokens", list_tokens, methods=["GET"]),
        Route("/api/tokens", create_token, methods=["POST"]),
        Route("/api/tokens/{token_id}", revoke_token, methods=["DELETE"]),
        Route("/api/tokens/{token_id}/rotate", rotate_token, methods=["POST"]),
        Route("/api/tokens/{token_id}/reactivate", reactivate_token, methods=["POST"]),
        Route("/api/case/create", post_case_create, methods=["POST"]),
        Route("/api/cases", get_cases, methods=["GET"]),
        Route("/api/case/activate/challenge", get_case_activate_challenge, methods=["GET"]),
        Route("/api/case/activate", post_case_activate, methods=["POST"]),
        # Phase 6.3: Portal Backends & Services Proxy Routes
        Route("/api/backends", get_backends_route, methods=["GET"]),
        Route("/api/backends", register_backend_route, methods=["POST"]),
        Route("/api/backends/{name}", unregister_backend_route, methods=["DELETE"]),
        Route("/api/backends/validate", validate_backend_route, methods=["POST"]),
        Route("/api/backends/reload", reload_backends_route, methods=["POST"]),
        Route("/api/services/{name}/start", start_service_route, methods=["POST"]),
        Route("/api/services/{name}/stop", stop_service_route, methods=["POST"]),
        Route("/api/services/{name}/restart", restart_service_route, methods=["POST"]),
    ]


def _verify_origin(request: Request) -> JSONResponse | None:
    origin = request.headers.get("origin")
    if not origin:
        return JSONResponse({"error": "Missing Origin header"}, status_code=400)
    host = request.headers.get("host")
    from urllib.parse import urlparse
    parsed_origin = urlparse(origin)
    origin_host = parsed_origin.netloc
    if not origin_host or origin_host != host:
        if origin_host.replace("localhost", "127.0.0.1") != host.replace("localhost", "127.0.0.1"):
            return JSONResponse({"error": f"Origin mismatch: {origin_host} vs {host}"}, status_code=400)
    return None


def _verify_password_challenge_helper(body: dict, client_host: str, examiner: str) -> JSONResponse | None:
    challenge_id = body.pop("challenge_id", None)
    response_hmac = body.pop("response", None)

    if not challenge_id or not response_hmac:
        return JSONResponse(
            {"error": "Missing challenge_id or response"}, status_code=400
        )

    challenge = _challenges.pop(challenge_id, None)
    if not challenge:
        return JSONResponse({"error": "Invalid or expired challenge"}, status_code=401)

    if challenge.get("bound_ip") != client_host:
        return JSONResponse({"error": "Challenge IP mismatch"}, status_code=403)

    now = time.time()
    if now - challenge["created_at"] > _CHALLENGE_TTL:
        return JSONResponse({"error": "Challenge expired"}, status_code=401)

    if challenge["examiner"] != examiner:
        return JSONResponse({"error": "Challenge/examiner mismatch"}, status_code=401)

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
        return JSONResponse({"error": "Incorrect password"}, status_code=401)

    _clear_commit_failures(examiner)
    return None


async def get_backends_route(request: Request) -> JSONResponse:
    examiner = getattr(request.state, "examiner", None)
    if not examiner:
        return JSONResponse({"error": "Authentication required"}, status_code=401)
    role_err = _require_portal_role(request)
    if role_err:
        return role_err
    gateway = getattr(request.app.state, "gateway", None) or _resolve_gateway(request)
    if not gateway:
        return JSONResponse({"error": "Gateway reference not found"}, status_code=503)
    from sift_gateway.rest import list_backends
    request.app.state.gateway = gateway
    return await list_backends(request)


async def validate_backend_route(request: Request) -> JSONResponse:
    examiner = getattr(request.state, "examiner", None)
    if not examiner:
        return JSONResponse({"error": "Authentication required"}, status_code=401)
    role_err = _require_examiner_role(request)
    if role_err:
        return role_err
    origin_err = _verify_origin(request)
    if origin_err:
        return origin_err
    gateway = getattr(request.app.state, "gateway", None) or _resolve_gateway(request)
    if not gateway:
        return JSONResponse({"error": "Gateway reference not found"}, status_code=503)

    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"error": "Invalid JSON body"}, status_code=400)

    from sift_gateway.rest import validate_backend_logic
    response, status_code = validate_backend_logic(gateway, body)
    return JSONResponse(response, status_code=status_code)


async def register_backend_route(request: Request) -> JSONResponse:
    examiner = getattr(request.state, "examiner", None)
    if not examiner:
        return JSONResponse({"error": "Authentication required"}, status_code=401)
    role_err = _require_examiner_role(request)
    if role_err:
        return role_err
    origin_err = _verify_origin(request)
    if origin_err:
        return origin_err
    gateway = getattr(request.app.state, "gateway", None) or _resolve_gateway(request)
    if not gateway:
        return JSONResponse({"error": "Gateway reference not found"}, status_code=503)

    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"error": "Invalid JSON body"}, status_code=400)

    examiner_name = _resolve_examiner(request)
    if not examiner_name:
        return JSONResponse({"error": "No examiner identity"}, status_code=401)
    client_host = request.client.host if request.client else "unknown"
    challenge_err = _verify_password_challenge_helper(body, client_host, examiner_name)
    if challenge_err:
        return challenge_err

    actor = getattr(request.state, "principal", None) or getattr(request.state, "identity", None)
    from sift_gateway.rest import register_backend_logic
    response, status_code = await register_backend_logic(gateway, body, actor=actor)
    return JSONResponse(response, status_code=status_code)


async def unregister_backend_route(request: Request) -> JSONResponse:
    examiner = getattr(request.state, "examiner", None)
    if not examiner:
        return JSONResponse({"error": "Authentication required"}, status_code=401)
    role_err = _require_examiner_role(request)
    if role_err:
        return role_err
    origin_err = _verify_origin(request)
    if origin_err:
        return origin_err
    gateway = getattr(request.app.state, "gateway", None) or _resolve_gateway(request)
    if not gateway:
        return JSONResponse({"error": "Gateway reference not found"}, status_code=503)

    try:
        body = await request.json()
    except Exception:
        body = {}

    examiner_name = _resolve_examiner(request)
    if not examiner_name:
        return JSONResponse({"error": "No examiner identity"}, status_code=401)
    client_host = request.client.host if request.client else "unknown"
    challenge_err = _verify_password_challenge_helper(body, client_host, examiner_name)
    if challenge_err:
        return challenge_err

    from sift_gateway.rest import unregister_backend

    request.app.state.gateway = gateway
    return await unregister_backend(request)


async def reload_backends_route(request: Request) -> JSONResponse:
    examiner = getattr(request.state, "examiner", None)
    if not examiner:
        return JSONResponse({"error": "Authentication required"}, status_code=401)
    role_err = _require_examiner_role(request)
    if role_err:
        return role_err
    origin_err = _verify_origin(request)
    if origin_err:
        return origin_err
    gateway = getattr(request.app.state, "gateway", None) or _resolve_gateway(request)
    if not gateway:
        return JSONResponse({"error": "Gateway reference not found"}, status_code=503)

    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"error": "Invalid JSON body"}, status_code=400)

    examiner_name = _resolve_examiner(request)
    if not examiner_name:
        return JSONResponse({"error": "No examiner identity"}, status_code=401)
    client_host = request.client.host if request.client else "unknown"
    challenge_err = _verify_password_challenge_helper(body, client_host, examiner_name)
    if challenge_err:
        return challenge_err

    from sift_gateway.rest import reload_backends
    request.app.state.gateway = gateway
    return await reload_backends(request)


async def start_service_route(request: Request) -> JSONResponse:
    examiner = getattr(request.state, "examiner", None)
    if not examiner:
        return JSONResponse({"error": "Authentication required"}, status_code=401)
    role_err = _require_examiner_role(request)
    if role_err:
        return role_err
    origin_err = _verify_origin(request)
    if origin_err:
        return origin_err
    gateway = getattr(request.app.state, "gateway", None) or _resolve_gateway(request)
    if not gateway:
        return JSONResponse({"error": "Gateway reference not found"}, status_code=503)

    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"error": "Invalid JSON body"}, status_code=400)

    examiner_name = _resolve_examiner(request)
    if not examiner_name:
        return JSONResponse({"error": "No examiner identity"}, status_code=401)
    client_host = request.client.host if request.client else "unknown"
    challenge_err = _verify_password_challenge_helper(body, client_host, examiner_name)
    if challenge_err:
        return challenge_err

    from sift_gateway.rest import start_service
    request.app.state.gateway = gateway
    return await start_service(request)


async def stop_service_route(request: Request) -> JSONResponse:
    examiner = getattr(request.state, "examiner", None)
    if not examiner:
        return JSONResponse({"error": "Authentication required"}, status_code=401)
    role_err = _require_examiner_role(request)
    if role_err:
        return role_err
    origin_err = _verify_origin(request)
    if origin_err:
        return origin_err
    gateway = getattr(request.app.state, "gateway", None) or _resolve_gateway(request)
    if not gateway:
        return JSONResponse({"error": "Gateway reference not found"}, status_code=503)

    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"error": "Invalid JSON body"}, status_code=400)

    examiner_name = _resolve_examiner(request)
    if not examiner_name:
        return JSONResponse({"error": "No examiner identity"}, status_code=401)
    client_host = request.client.host if request.client else "unknown"
    challenge_err = _verify_password_challenge_helper(body, client_host, examiner_name)
    if challenge_err:
        return challenge_err

    from sift_gateway.rest import stop_service
    request.app.state.gateway = gateway
    return await stop_service(request)


async def restart_service_route(request: Request) -> JSONResponse:
    examiner = getattr(request.state, "examiner", None)
    if not examiner:
        return JSONResponse({"error": "Authentication required"}, status_code=401)
    role_err = _require_examiner_role(request)
    if role_err:
        return role_err
    origin_err = _verify_origin(request)
    if origin_err:
        return origin_err
    gateway = getattr(request.app.state, "gateway", None) or _resolve_gateway(request)
    if not gateway:
        return JSONResponse({"error": "Gateway reference not found"}, status_code=503)

    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"error": "Invalid JSON body"}, status_code=400)

    examiner_name = _resolve_examiner(request)
    if not examiner_name:
        return JSONResponse({"error": "No examiner identity"}, status_code=401)
    client_host = request.client.host if request.client else "unknown"
    challenge_err = _verify_password_challenge_helper(body, client_host, examiner_name)
    if challenge_err:
        return challenge_err

    from sift_gateway.rest import restart_service
    request.app.state.gateway = gateway
    return await restart_service(request)



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
    token_registry=None,
    on_chain_mutation: Callable[[str], None] | None = None,
    on_case_activated: Callable[[str], object] | None = None,
    on_override_get_status: Callable[[str], dict] | None = None,
    on_override_enable: Callable[[str, str, int], dict] | None = None,
    on_override_cancel: Callable[[str], None] | None = None,
    *,
    supabase_auth=None,
    active_case_service=None,
    evidence_service=None,
    investigation_service=None,
    report_service=None,
    job_service=None,
    legacy_portal_session_enabled: bool = True,
) -> Starlette:
    """Create the v2 dashboard sub-app for mounting on the gateway.

    Args:
        session_secret: JWT signing secret from portal.session_secret.
        session_max_age: Session lifetime in seconds (default 8 h).
        api_keys: Reference to the live gateway api_keys dict. Token lifecycle
            endpoints mutate this dict in place so changes are immediately
            honoured by the auth middleware without a restart.
        gateway_config_path: Absolute path to gateway.yaml for legacy case
            activation writes.
        token_registry: DB-backed hash-only MCP/service token registry. Required
            for token lifecycle writes in PR02.
        on_chain_mutation: Called with case_dir_str after every evidence chain
            seal or ignore. The gateway passes invalidate_evidence_cache so the
            30s TTL cache is dropped immediately on portal seal.
        on_case_activated: Called with case_dir_str after portal case creation
            updates SIFT_CASE_DIR. The gateway passes an async callback that
            restarts stdio backends so they inherit the new case directory.
        on_override_get_status / on_override_enable / on_override_cancel:
            Bound to response_guard.get_override_status / enable_override /
            cancel_override by the gateway. Required for response-guard portal
            endpoints; absent in tests returns a 503 / warning response.
        supabase_auth: PR03A C3 callback boundary. A Gateway-injected object whose
            async methods (login/resolve/refresh/issue_principal/revoke_principal/
            logout/list_principals) return plain dicts (or None, or raise an
            exception carrying int .http_status and str .reason). case_dashboard
            never imports sift_gateway; all Supabase/principal logic is reached
            through this object. When None, the portal uses the legacy auth path.
        active_case_service: PR03B Gateway-injected DB active-case service. When
            present, case list/create/activate/metadata use Postgres authority
            and never write active-case env/config/pointer exports.
        evidence_service: BATCH-E1 Gateway-injected DB evidence authority over the
            C1 custody RPCs. When present, evidence read + seal/ignore/retire use
            Postgres authority; seal/ignore/retire pass the re-auth audit event id
            produced by the portal's password/HMAC re-auth. When None, the legacy
            file-backed evidence-chain path is used.
        investigation_service: BATCH-E1 Gateway-injected DB authority for
            findings/timeline/iocs/todos read + todo create/update/delete. Agent
            proposals stay proposed/draft until a human approves them. When None,
            the legacy file-backed path is used.
        report_service: BATCH-E1 Gateway-injected DB report-metadata authority
            (list_reports / report_eligibility / addon_status). Report GENERATION
            internals are owned by BATCH-J1; this only wires metadata/eligibility/
            approval visibility. When None, the legacy file-backed reports path
            is used.
        job_service: D2 Gateway job/status adapter (JobService). Backs
            GET /api/jobs/{job_id} with the sanitized, case-scoped status. When
            None, the job-status route returns 503.
        legacy_portal_session_enabled: When false, disables the legacy PBKDF2
            challenge/login, the sift_session HMAC cookie, and the examiner Bearer
            fallback. Defaults to True so existing suites and non-Supabase
            deployments keep working; the Gateway passes
            auth.legacy.portal_session_enabled.
    """
    from case_dashboard.auth import PortalSessionMiddleware

    global _SESSION_SECRET, _SESSION_MAX_AGE, _API_KEYS, _GATEWAY_CONFIG_PATH
    global _TOKEN_REGISTRY
    global _ON_CHAIN_MUTATION, _OVERRIDE_GET_STATUS, _OVERRIDE_ENABLE, _OVERRIDE_CANCEL
    global _ON_CASE_ACTIVATED
    global _SUPABASE_AUTH, _ACTIVE_CASES, _LEGACY_PORTAL_SESSION_ENABLED
    global _EVIDENCE_DB, _INVESTIGATION_DB, _REPORT_DB, _JOB_SERVICE
    _SESSION_SECRET = session_secret
    _SESSION_MAX_AGE = session_max_age
    _API_KEYS = api_keys if api_keys is not None else {}
    _GATEWAY_CONFIG_PATH = Path(gateway_config_path) if gateway_config_path else None
    _TOKEN_REGISTRY = token_registry
    _ON_CHAIN_MUTATION = on_chain_mutation
    _ON_CASE_ACTIVATED = on_case_activated
    _OVERRIDE_GET_STATUS = on_override_get_status
    _OVERRIDE_ENABLE = on_override_enable
    _OVERRIDE_CANCEL = on_override_cancel
    _SUPABASE_AUTH = supabase_auth
    _ACTIVE_CASES = active_case_service
    _EVIDENCE_DB = evidence_service
    _INVESTIGATION_DB = investigation_service
    _REPORT_DB = report_service
    _JOB_SERVICE = job_service
    _LEGACY_PORTAL_SESSION_ENABLED = legacy_portal_session_enabled
    routes = _dashboard_api_routes()
    routes.append(Route("/assets/{filename:path}", serve_v2_assets, methods=["GET"]))
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
                supabase_auth=supabase_auth,
                legacy_portal_session_enabled=legacy_portal_session_enabled,
            ),
            Middleware(SecurityHeadersMiddleware),
        ],
    )
