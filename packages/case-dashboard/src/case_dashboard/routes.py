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
import inspect
import uuid
from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path

import yaml
from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import FileResponse, JSONResponse, Response
from starlette.routing import Route

from sift_core.approval_auth import (
    _load_password_entry as _load_pw_entry,
    _save_password_entry as _save_pw_entry,
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
    anchor_manifest,
    chain_status,
    retire_file,
    diff_manifest,
    get_immutable_flag,
    ignore_file,
    init_evidence_chain,
    load_anchor_proof,
    load_ledger,
    load_manifest,
    seal_manifest,
    verify_chain_hmac,
)
from sift_core.verification import compute_hmac, write_ledger_entry
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
_PASSWORDS_DIR = Path("/var/lib/sift/passwords")

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
_CASE_ID_RE = re.compile(r"^[a-z][a-z0-9_-]{2,63}$")
_CASE_SLUG_INVALID_RE = re.compile(r"[^a-z0-9_-]+")
_CASE_SLUG_HYPHENS_RE = re.compile(r"-+")

# Evidence chain challenge store — domain-separated from commit challenges (R2)
_evidence_challenges: dict[str, dict] = {}
_EVIDENCE_CHALLENGE_TTL = 30  # seconds

# Case activation challenge store — domain-separated
_activation_challenges: dict[str, dict] = {}
_ACTIVATION_CHALLENGE_TTL = 30  # seconds

# HMAC verify state file — records when the examiner last ran a full ledger HMAC verify
_VERIFY_STATE_FILE = "evidence-verify-state.json"
_HMAC_VERIFY_REMIND_HOURS = 24  # remind if no verify within this window

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
    """Resolve case directory per-request.

    Priority: SIFT_CASE_DIR env var (set via gateway.yaml case.dir).
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
        {"error": "No active case. Set SIFT_CASE_DIR in gateway.yaml case.dir."},
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


def _read_verify_state(case_dir: Path) -> dict:
    """Read the HMAC verify state file. Returns {} on missing/parse error."""
    try:
        path = case_dir / _VERIFY_STATE_FILE
        if path.exists():
            return json.loads(path.read_text())
    except (OSError, json.JSONDecodeError):
        pass
    return {}


def _hmac_verify_needed(state: dict) -> bool:
    """Return True if last HMAC verify is absent or older than the reminder window."""
    last = state.get("last_hmac_verified_at")
    if not last:
        return True
    try:
        from datetime import datetime, timezone
        ts = datetime.fromisoformat(last)
        age_hours = (datetime.now(timezone.utc) - ts).total_seconds() / 3600
        return age_hours >= _HMAC_VERIFY_REMIND_HOURS
    except (ValueError, TypeError):
        return True


def _build_evidence_chain_status(case_dir: Path) -> dict:
    """Assemble the full evidence chain status payload for portal display."""
    status = chain_status(case_dir)
    manifest = load_manifest(case_dir)
    diff: dict = {}
    if manifest:
        diff = diff_manifest(case_dir, manifest)

    evidence_dir = case_dir / "evidence"
    wb = _detect_write_block(evidence_dir)

    verify_state = _read_verify_state(case_dir)
    manifest_version = status["manifest_version"]

    # Anchor status (Phase 16e)
    keypair_configured = bool(os.environ.get("SIFT_SOLANA_KEYPAIR", "").strip())
    anchor_proof = load_anchor_proof(case_dir, manifest_version) if manifest_version > 0 else None
    anchor_info: dict = {"anchoring_enabled": keypair_configured, "manifest_version": manifest_version}
    if anchor_proof:
        anchor_info.update({
            "solana_tx": anchor_proof.get("solana_tx"),
            "confirmed": anchor_proof.get("confirmed", False),
            "cluster": anchor_proof.get("solana_cluster", "mainnet"),
            "timestamp": anchor_proof.get("timestamp"),
            "explorer_url": anchor_proof.get("explorer_url"),
        })

    # Immutable flag per ACTIVE file (Phase 17a)
    immutable_flags: dict[str, bool | None] = {}
    if manifest:
        for entry in manifest.get("files", []):
            if entry.get("status") == "ACTIVE":
                rel = entry["path"]
                immutable_flags[rel] = get_immutable_flag(case_dir / rel)

    return {
        "status": status["status"],
        "issues": status["issues"],
        "manifest_version": manifest_version,
        "ok_count": status.get("ok_count", 0),
        "unregistered": diff.get("unregistered", []),
        "missing": diff.get("missing", []),
        "modified": diff.get("modified", []),
        "ok": diff.get("ok", []),
        "write_protected": wb.get("write_protected", False),
        "write_block_warning": wb.get("warning"),
        "write_block_mount_point": wb.get("mount_point"),
        "hmac_last_verified_at": verify_state.get("last_hmac_verified_at"),
        "hmac_last_verified_by": verify_state.get("last_hmac_verified_by"),
        "hmac_verify_needed": _hmac_verify_needed(verify_state),
        "anchor": anchor_info,
        "immutable_flags": immutable_flags,
    }


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


# ---------------------------------------------------------------------------
# Evidence chain endpoint handlers (Phase 16a)
# ---------------------------------------------------------------------------


async def get_evidence_chain_status(request: Request) -> JSONResponse:
    """Return evidence chain status, diff, and write-block detection. No mutation."""
    role_err = _require_portal_role(request)
    if role_err:
        return role_err

    case_dir = _resolve_case_dir()
    if not case_dir:
        return _no_case_response()

    return JSONResponse(_build_evidence_chain_status(case_dir))


async def post_evidence_chain_rescan(request: Request) -> JSONResponse:
    """Drop the evidence gate cache and return a fresh status."""
    role_err = _require_examiner_role(request)
    if role_err:
        return role_err

    case_dir = _resolve_case_dir()
    if not case_dir:
        return _no_case_response()

    case_dir_str = os.environ.get("SIFT_CASE_DIR", "")
    if _ON_CHAIN_MUTATION and case_dir_str:
        try:
            _ON_CHAIN_MUTATION(case_dir_str)
        except Exception as exc:
            logger.warning("evidence rescan: cache invalidation failed: %s", exc)

    return JSONResponse(_build_evidence_chain_status(case_dir))


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
    })


async def post_evidence_chain_seal(request: Request) -> JSONResponse:
    """Seal a new evidence manifest version with HMAC confirmation.

    Body: {challenge_id, response, file_specs: [{path, source?, description?}]}
    Requires: session examiner + role examiner + must_reset_password=false + HMAC.
    """
    role_err = _require_examiner_role(request)
    if role_err:
        return role_err

    case_dir = _resolve_case_dir()
    if not case_dir:
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
    file_specs = body.get("file_specs", [])

    if not challenge_id or not response_hmac:
        return JSONResponse({"error": "Missing challenge_id or response"}, status_code=400)
    if not isinstance(file_specs, list):
        return JSONResponse({"error": "file_specs must be a list"}, status_code=400)

    err_msg, derived_key = _verify_evidence_hmac(
        examiner, challenge_id, response_hmac, request.client.host
    )
    if err_msg:
        return JSONResponse({"error": err_msg}, status_code=401)

    # Validate file_specs entries
    for spec in file_specs:
        if not isinstance(spec, dict) or "path" not in spec:
            return JSONResponse({"error": "Each file_spec must have a 'path' key"}, status_code=400)

    try:
        new_manifest = seal_manifest(case_dir, file_specs, examiner, derived_key)
    except FileNotFoundError as e:
        return JSONResponse({"error": str(e)}, status_code=400)
    except ValueError as e:
        return JSONResponse({"error": str(e)}, status_code=400)
    except Exception:
        logger.exception("Evidence seal failed")
        return JSONResponse({"error": "Seal failed — check gateway logs"}, status_code=500)

    case_dir_str = os.environ.get("SIFT_CASE_DIR", "")
    if _ON_CHAIN_MUTATION and case_dir_str:
        try:
            _ON_CHAIN_MUTATION(case_dir_str)
        except Exception as exc:
            logger.warning("evidence seal: cache invalidation failed: %s", exc)

    # Auto-anchor on Solana if keypair is configured (non-blocking — never fails the seal)
    anchor_info: dict | None = None
    keypair_path = os.environ.get("SIFT_SOLANA_KEYPAIR", "").strip() or None
    if keypair_path:
        try:
            cluster = os.environ.get("SIFT_SOLANA_CLUSTER", "mainnet")
            ledger = load_ledger(case_dir)
            proof = anchor_manifest(case_dir, new_manifest, ledger, keypair_path=keypair_path, cluster=cluster)
            anchor_info = {
                "solana_tx": proof.get("solana_tx"),
                "confirmed": proof.get("confirmed"),
                "explorer_url": proof.get("explorer_url"),
            }
        except Exception as exc:
            logger.warning("evidence seal: anchor_manifest failed: %s", exc)

    resp: dict = {
        "sealed": True,
        "manifest_version": new_manifest["version"],
        "files_added": [s["path"] for s in file_specs],
    }
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

    case_dir = _resolve_case_dir()
    if not case_dir:
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
    rel_path = str(body.get("path", "")).strip()
    reason = str(body.get("reason", "")).strip()

    if not challenge_id or not response_hmac:
        return JSONResponse({"error": "Missing challenge_id or response"}, status_code=400)
    if not rel_path:
        return JSONResponse({"error": "Missing path"}, status_code=400)
    if not reason:
        return JSONResponse({"error": "Missing reason"}, status_code=400)

    err_msg, derived_key = _verify_evidence_hmac(
        examiner, challenge_id, response_hmac, request.client.host
    )
    if err_msg:
        return JSONResponse({"error": err_msg}, status_code=401)

    try:
        ignore_file(case_dir, rel_path, examiner, derived_key, reason)
    except ValueError as e:
        return JSONResponse({"error": str(e)}, status_code=400)
    except Exception:
        logger.exception("Evidence ignore failed")
        return JSONResponse({"error": "Ignore failed — check gateway logs"}, status_code=500)

    case_dir_str = os.environ.get("SIFT_CASE_DIR", "")
    if _ON_CHAIN_MUTATION and case_dir_str:
        try:
            _ON_CHAIN_MUTATION(case_dir_str)
        except Exception as exc:
            logger.warning("evidence ignore: cache invalidation failed: %s", exc)

    return JSONResponse({
        "ignored": True,
        "path": rel_path,
        "manifest_version": (load_manifest(case_dir) or {}).get("version", -1),
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

    case_dir = _resolve_case_dir()
    if not case_dir:
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
    rel_path = str(body.get("path", "")).strip()
    reason = str(body.get("reason", "")).strip()

    if not challenge_id or not response_hmac:
        return JSONResponse({"error": "Missing challenge_id or response"}, status_code=400)
    if not rel_path:
        return JSONResponse({"error": "Missing path"}, status_code=400)
    if not reason:
        return JSONResponse({"error": "Missing reason"}, status_code=400)

    err_msg, derived_key = _verify_evidence_hmac(
        examiner, challenge_id, response_hmac, request.client.host
    )
    if err_msg:
        return JSONResponse({"error": err_msg}, status_code=401)

    try:
        retire_file(case_dir, rel_path, reason, examiner, derived_key)
    except ValueError as e:
        return JSONResponse({"error": str(e)}, status_code=400)
    except Exception:
        logger.exception("Evidence retire failed")
        return JSONResponse({"error": "Retire failed — check gateway logs"}, status_code=500)

    # Delete the file from disk now that the immutable flag is cleared and ledger is updated
    abs_path = case_dir / rel_path
    deleted = False
    if abs_path.exists():
        try:
            abs_path.unlink()
            deleted = True
        except OSError as e:
            logger.warning("retire: file unlink failed for %s: %s", abs_path, e)

    case_dir_str = os.environ.get("SIFT_CASE_DIR", "")
    if _ON_CHAIN_MUTATION and case_dir_str:
        try:
            _ON_CHAIN_MUTATION(case_dir_str)
        except Exception as exc:
            logger.warning("evidence retire: cache invalidation failed: %s", exc)

    return JSONResponse({
        "retired": True,
        "path": rel_path,
        "deleted_from_disk": deleted,
        "manifest_version": (load_manifest(case_dir) or {}).get("version", -1),
    })


# ---------------------------------------------------------------------------
# Evidence chain HMAC verify endpoint (Phase 16-verify-remind)
# ---------------------------------------------------------------------------


async def post_evidence_chain_verify_hmac(request: Request) -> JSONResponse:
    """Run a full HMAC verification of every ledger event with HMAC confirmation.

    Records the timestamp on success so the portal can remind the examiner when
    more than _HMAC_VERIFY_REMIND_HOURS have elapsed since the last verify.

    Body: {challenge_id, response}
    Requires: session examiner + role examiner + must_reset_password=false + HMAC.
    Returns: {ok, verified, failed, failed_indices, verified_at, verified_by}
    """
    role_err = _require_examiner_role(request)
    if role_err:
        return role_err

    case_dir = _resolve_case_dir()
    if not case_dir:
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

    if not challenge_id or not response_hmac:
        return JSONResponse({"error": "Missing challenge_id or response"}, status_code=400)

    err_msg, derived_key = _verify_evidence_hmac(
        examiner, challenge_id, response_hmac, request.client.host
    )
    if err_msg:
        return JSONResponse({"error": err_msg}, status_code=401)

    try:
        result = verify_chain_hmac(case_dir, derived_key)
    except Exception:
        logger.exception("verify_chain_hmac failed")
        return JSONResponse({"error": "HMAC verify failed — check gateway logs"}, status_code=500)

    from datetime import datetime, timezone
    verified_at = datetime.now(timezone.utc).isoformat()

    if result.get("ok"):
        # Record the successful verify timestamp
        state_path = case_dir / _VERIFY_STATE_FILE
        try:
            state_path.write_text(json.dumps({
                "last_hmac_verified_at": verified_at,
                "last_hmac_verified_by": examiner,
            }))
        except OSError as exc:
            logger.warning("verify_chain_hmac: failed to write state file: %s", exc)

    return JSONResponse({
        **result,
        "verified_at": verified_at,
        "verified_by": examiner,
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

    case_dir = _resolve_case_dir()
    if not case_dir:
        return _no_case_response()

    keypair_path = os.environ.get("SIFT_SOLANA_KEYPAIR", "").strip() or None
    if not keypair_path:
        return JSONResponse(
            {"error": "Solana anchoring not configured — set SIFT_SOLANA_KEYPAIR"},
            status_code=503,
        )

    manifest = load_manifest(case_dir)
    if not manifest or manifest.get("version", 0) == 0:
        return JSONResponse({"error": "No sealed manifest to anchor"}, status_code=400)

    try:
        cluster = os.environ.get("SIFT_SOLANA_CLUSTER", "mainnet")
        ledger = load_ledger(case_dir)
        proof = anchor_manifest(case_dir, manifest, ledger, keypair_path=keypair_path, cluster=cluster)
    except Exception:
        logger.exception("manual anchor_manifest failed")
        return JSONResponse({"error": "Anchor failed — check gateway logs"}, status_code=500)

    return JSONResponse({
        "anchored": proof.get("solana_tx") is not None,
        "manifest_version": proof.get("manifest_version"),
        "solana_tx": proof.get("solana_tx"),
        "confirmed": proof.get("confirmed"),
        "explorer_url": proof.get("explorer_url"),
        "cluster": proof.get("solana_cluster"),
    })


# ---------------------------------------------------------------------------
# Response-guard override endpoints (Approach C / Phase 16a-guard)
# ---------------------------------------------------------------------------


async def get_response_guard_status(request: Request) -> JSONResponse:
    """Return current response-guard override status. Session auth, no HMAC."""
    role_err = _require_portal_role(request)
    if role_err:
        return role_err

    case_dir_str = os.environ.get("SIFT_CASE_DIR", "")
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

    case_dir_str = os.environ.get("SIFT_CASE_DIR", "")
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

    case_dir_str = os.environ.get("SIFT_CASE_DIR", "")
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

    case_dir = _resolve_case_dir()
    if not case_dir:
        return _no_case_response()
    # The authoritative registered-evidence record is the SEALED manifest
    # (evidence-manifest.json). Sealing writes files into the manifest, not into
    # evidence.json — reading evidence.json left the table empty and made sealed
    # files appear to "disappear" after verify+seal. Prefer the manifest's ACTIVE
    # files, falling back to legacy evidence.json only when no manifest exists.
    manifest = load_manifest(case_dir)
    manifest_files = manifest.get("files", []) if manifest else []
    active_files = [e for e in manifest_files if e.get("status", "ACTIVE") == "ACTIVE"]
    if active_files:
        evidence = [
            {
                "path": e.get("path", ""),
                "sha256": e.get("sha256", ""),
                "size_bytes": e.get("bytes"),
                "source": e.get("source", ""),
                "description": e.get("description", ""),
                "registered_at": e.get("registered_at", ""),
                "registered_by": e.get("registered_by") or e.get("sealed_by") or "",
                "status": e.get("status", "ACTIVE"),
            }
            for e in active_files
        ]
    else:
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
    examiner = _resolve_examiner(request)
    if not examiner:
        return JSONResponse({"error": "Authentication required"}, status_code=401)
    role_err = _require_portal_role(request)
    if role_err:
        return role_err

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
    case_dir = _resolve_case_dir()
    if not case_dir:
        return _no_case_response()

    try:
        body = await request.json()
    except json.JSONDecodeError:
        return JSONResponse({"error": "Invalid JSON body"}, status_code=400)
    if not isinstance(body, dict):
        return JSONResponse({"error": "Request body must be a JSON object"}, status_code=400)

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
    if not case_dir:
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
    if not case_dir:
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
    if not case_dir:
        return _no_case_response()
    examiner = _resolve_examiner(request)
    if not examiner:
        return JSONResponse({"error": "Authentication required"}, status_code=401)
    err = _must_reset_check(examiner)
    if err:
        return err

    todo_id = request.path_params["todo_id"]
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
    required = not has_any
    return JSONResponse({"required": required, "setup_required": required})


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

    if not found_info.get("revoked_at"):
        return JSONResponse({"error": "Token is not revoked (already active)"}, status_code=409)

    found_info["revoked_at"] = None

    try:
        with _GATEWAY_CONFIG_LOCK:
            _token_config_write({found_raw: found_info})
    except (OSError, RuntimeError) as e:
        logger.error("Failed to reactivate token %s: %s", token_id, e)
        return JSONResponse(
            {"error": "Failed to reactivate token — check gateway logs"},
            status_code=500,
        )

    logger.info("Service token reactivated: token_id=%s by=%s", token_id, examiner)
    return JSONResponse({"ok": True, "token_id": token_id})


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


def _valid_case_id(case_id: str) -> bool:
    return bool(_CASE_ID_RE.fullmatch(case_id))


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
    """GET /portal/api/cases — List all cases under the cases root."""
    examiner = _resolve_examiner(request)
    if not examiner:
        return JSONResponse({"error": "Authentication required"}, status_code=401)
    role_err = _require_portal_role(request)
    if role_err:
        return role_err

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
    """POST /portal/api/case/activate — Activate an existing case with password confirmation."""
    examiner = _resolve_examiner(request)
    if not examiner:
        return JSONResponse({"error": "Authentication required"}, status_code=401)
    role_err = _require_examiner_role(request)
    if role_err:
        return role_err

    lockout_msg = _check_commit_lockout(f"activate:{examiner}")
    if lockout_msg:
        return JSONResponse({"error": lockout_msg}, status_code=429)

    err = _must_reset_check(examiner)
    if err:
        return err

    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"error": "Invalid JSON"}, status_code=400)

    if not isinstance(body, dict):
        return JSONResponse({"error": "Expected JSON object"}, status_code=400)

    case_id = body.get("case_id", "").strip()
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
        # Update gateway.yaml config atomically if configured
        if _GATEWAY_CONFIG_PATH is not None:
            try:
                with _GATEWAY_CONFIG_LOCK:
                    _case_config_write(str(real_requested))
            except Exception as e:
                logger.error("Failed to update gateway config with case dir: %s", e)
                return JSONResponse({"error": "Failed to update gateway config"}, status_code=500)

        # Update environment variable in-process
        os.environ["SIFT_CASE_DIR"] = str(real_requested)
        os.environ["SIFT_CASES_ROOT"] = str(real_root)
        try:
            _write_cli_case_pointer(str(real_requested))
        except OSError as e:
            logger.error("Failed to update legacy CLI case pointer: %s", e)
            return JSONResponse(
                {"error": "Failed to update legacy CLI case pointer"},
                status_code=500,
            )

        if _ON_CASE_ACTIVATED is not None:
            maybe_awaitable = _ON_CASE_ACTIVATED(str(real_requested))
            if inspect.isawaitable(maybe_awaitable):
                await maybe_awaitable
        else:
            gateway = _resolve_gateway(request)
            if gateway:
                if hasattr(gateway, "config") and isinstance(gateway.config, dict):
                    if "case" not in gateway.config:
                        gateway.config["case"] = {}
                    gateway.config["case"]["dir"] = str(real_requested)

                if hasattr(gateway, "restart_backends"):
                    await gateway.restart_backends()

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

    if not casename or not title:
        return JSONResponse({"error": "Missing required fields"}, status_code=400)

    if casename != casename.lower():
        return JSONResponse({"error": "casename must be lowercase"}, status_code=400)

    slug = _slugify_case_name(casename)
    case_id = f"{slug}-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M')}"
    if not _valid_case_id(case_id):
        return JSONResponse({"error": "Invalid case_id format"}, status_code=400)

    real_root = _load_cases_root()
    real_requested = (real_root / case_id).resolve()
    if not real_requested.is_relative_to(real_root):
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

        # Update gateway.yaml config atomically if configured
        if _GATEWAY_CONFIG_PATH is not None:
            try:
                with _GATEWAY_CONFIG_LOCK:
                    _case_config_write(str(real_requested))
            except Exception as e:
                logger.error("Failed to update gateway config with case dir: %s", e)
                return JSONResponse({"error": "Failed to update gateway config"}, status_code=500)

        # Update environment variable in-process
        os.environ["SIFT_CASE_DIR"] = str(real_requested)
        os.environ["SIFT_CASES_ROOT"] = str(real_root)
        try:
            _write_cli_case_pointer(str(real_requested))
        except OSError as e:
            logger.error("Failed to update legacy CLI case pointer: %s", e)
            return JSONResponse(
                {"error": "Failed to update legacy CLI case pointer"},
                status_code=500,
            )

        if _ON_CASE_ACTIVATED is not None:
            maybe_awaitable = _ON_CASE_ACTIVATED(str(real_requested))
            if inspect.isawaitable(maybe_awaitable):
                await maybe_awaitable
        else:
            # Restart backends when no explicit parent-gateway callback was wired.
            gateway = _resolve_gateway(request)
            if gateway:
                if hasattr(gateway, "config") and isinstance(gateway.config, dict):
                    if "case" not in gateway.config:
                        gateway.config["case"] = {}
                    gateway.config["case"]["dir"] = str(real_requested)

                if hasattr(gateway, "restart_backends"):
                    await gateway.restart_backends()

        return JSONResponse(
            {"ok": True, "case_id": case_id, "case_dir": str(real_requested)}
        )

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

    return "\n".join(md)


async def get_reports(request: Request) -> JSONResponse:
    examiner = _resolve_examiner(request)
    if not examiner:
        return JSONResponse({"error": "Authentication required"}, status_code=401)
    role_err = _require_examiner_role(request)
    if role_err:
        return role_err

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

        from sift_core.reporting import generate_report_data
        result = generate_report_data(
            profile_name=profile,
            case_dir=case_dir,
            finding_ids=finding_ids,
            start_date=start_date,
            end_date=end_date,
        )

        if isinstance(result, dict) and "error" in result:
             logger.error("Report generation internal error: %s", result["error"])
             return JSONResponse({"error": "Report generation failed. Check the case status."}, status_code=500)

        report_id = str(uuid.uuid4())
        result["id"] = report_id
        result["examiner"] = examiner
        result["created_at"] = datetime.now(timezone.utc).isoformat()

        _PENDING_REPORTS[report_id] = result

        response_payload = {
            "id": report_id,
            "profile": profile,
            "report_data": result.get("report_data"),
            "sections": result.get("sections"),
            "guidance": result.get("writing_guidance"),
            "evidence_chain": result.get("evidence_chain"),
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

        headers = {
            "Content-Disposition": f'attachment; filename="{filename}"',
            "Content-Type": "text/markdown; charset=utf-8",
        }
        return Response(markdown_content, headers=headers)
    except Exception as e:
        logger.exception("Failed to serialize/download report: %s", e)
        return Response("Failed to generate markdown report.", status_code=500)


def _dashboard_api_routes() -> list[Route]:
    """API routes shared by v1 and v2 dashboard apps."""
    return [
        Route("/api/reports", get_reports, methods=["GET"]),
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
        Route("/api/evidence/chain/retire", post_evidence_chain_retire, methods=["POST"]),
        Route("/api/evidence/chain/verify-hmac", post_evidence_chain_verify_hmac, methods=["POST"]),
        Route("/api/evidence/chain/anchor", post_evidence_chain_anchor, methods=["POST"]),
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
        Route("/api/auth/logout", post_auth_logout, methods=["POST"]),
        Route("/api/auth/me", get_auth_me, methods=["GET"]),
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

    from sift_gateway.rest import register_backend_logic
    response, status_code = await register_backend_logic(gateway, body)
    return JSONResponse(response, status_code=status_code)


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
    on_chain_mutation: Callable[[str], None] | None = None,
    on_case_activated: Callable[[str], object] | None = None,
    on_override_get_status: Callable[[str], dict] | None = None,
    on_override_enable: Callable[[str, str, int], dict] | None = None,
    on_override_cancel: Callable[[str], None] | None = None,
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
    """
    from case_dashboard.auth import PortalSessionMiddleware

    global _SESSION_SECRET, _SESSION_MAX_AGE, _API_KEYS, _GATEWAY_CONFIG_PATH
    global _ON_CHAIN_MUTATION, _OVERRIDE_GET_STATUS, _OVERRIDE_ENABLE, _OVERRIDE_CANCEL
    global _ON_CASE_ACTIVATED
    _SESSION_SECRET = session_secret
    _SESSION_MAX_AGE = session_max_age
    _API_KEYS = api_keys if api_keys is not None else {}
    _GATEWAY_CONFIG_PATH = Path(gateway_config_path) if gateway_config_path else None
    _ON_CHAIN_MUTATION = on_chain_mutation
    _ON_CASE_ACTIVATED = on_case_activated
    _OVERRIDE_GET_STATUS = on_override_get_status
    _OVERRIDE_ENABLE = on_override_enable
    _OVERRIDE_CANCEL = on_override_cancel
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
            ),
            Middleware(SecurityHeadersMiddleware),
        ],
    )
