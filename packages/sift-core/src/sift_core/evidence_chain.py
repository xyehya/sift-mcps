"""Evidence manifest and chain-of-custody.

Authority: evidence-manifest.json + evidence-ledger.jsonl.
Compatibility view: evidence.json (unchanged — kept for existing tools).

Gateway path: chain_status() — stat-check + structural hash-chain verify; no key needed.
Portal path: seal_manifest(), ignore_file(), retire_file(), verify_chain_hmac() — require derived_key.
Full SHA-256 rehash of files is triggered only by seal_manifest() and explicit verify calls.

mtime_ns is recorded for informational context only. Never used in integrity assertions.

File statuses in manifest:
  ACTIVE     — registered, included in integrity checks
  IGNORED    — examiner decision: unregistered file intentionally excluded
  RETIRED    — examiner decision: previously registered file deliberately removed
"""

from __future__ import annotations

import ctypes
import fcntl
import hashlib
import hmac
import json
import logging
import os
import pwd
import tempfile
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path

logger = logging.getLogger(__name__)

# Default service user the gateway/worker run as. install.sh creates this
# dedicated non-admin account. Ownership of sealed bytes is reported as
# informational context only (never enforced); the load-bearing integrity
# property is the immutable flag, which the service user can set/clear in-process
# via CAP_LINUX_IMMUTABLE (granted to the venv interpreter by install.sh).
DEFAULT_SERVICE_USER = "sift-service"


class EvidenceHardeningError(RuntimeError):
    """Sealed-evidence filesystem hardening could not be applied.

    Raised so the seal path fails CLOSED: the operator must never believe a file
    is immutable (sealed) when the integrity posture was not actually achieved on
    disk.
    """


class ChainStatus(str, Enum):
    OK = "ok"
    UNSEALED = "unsealed"       # no sealed manifest (version=0, no files)
    MODIFIED = "modified"       # registered file has different byte size
    MISSING = "missing"         # registered file not found on disk
    UNREGISTERED = "unregistered"  # unknown file in evidence/
    LEDGER_ERROR = "ledger_error"  # hash-chain broken or manifest hash mismatch


_MANIFEST_FILE = "evidence-manifest.json"
_LEDGER_FILE = "evidence-ledger.jsonl"
_EVIDENCE_SUBDIR = "evidence"


def _records_dir(case_dir: Path) -> Path:
    from sift_core.case_io import case_records_dir

    path = case_records_dir(case_dir)
    path.mkdir(parents=True, exist_ok=True)
    return path


def manifest_path(case_dir: Path) -> Path:
    return _records_dir(case_dir) / _MANIFEST_FILE


def ledger_path(case_dir: Path) -> Path:
    return _records_dir(case_dir) / _LEDGER_FILE


def anchor_proof_path(case_dir: Path, version: int) -> Path:
    return _records_dir(case_dir) / _ANCHOR_PROOF_PATTERN.format(version=version)


def _tmp_case(case_dir: Path) -> bool:
    return str(case_dir.resolve()).startswith("/tmp/")


def _legacy_case_path(case_dir: Path, filename: str) -> Path:
    return case_dir / filename


def _atomic_write_json_with_tmp_shadow(case_dir: Path, path: Path, data: dict, filename: str) -> None:
    _atomic_write_json(path, data)
    if _tmp_case(case_dir):
        _atomic_write_json(_legacy_case_path(case_dir, filename), data)


# ---------------------------------------------------------------------------
# Initialisation (called from case create — Phase 16g)
# ---------------------------------------------------------------------------

def init_evidence_chain(case_dir: Path) -> None:
    """Write empty evidence-manifest.json (version=0) and empty evidence-ledger.jsonl.

    Safe to call on a case that already has these files — skips if present.
    """
    m_path = manifest_path(case_dir)
    l_path = ledger_path(case_dir)

    if not m_path.exists():
        manifest: dict = {
            "version": 0,
            "case_id": _load_case_id(case_dir),
            "created_at": _now(),
            "created_by": "",
            "previous_manifest_hash": "",
            "manifest_hash": "",
            "files": [],
        }
        manifest["manifest_hash"] = compute_manifest_hash(manifest)
        _atomic_write_json_with_tmp_shadow(case_dir, m_path, manifest, _MANIFEST_FILE)

    if not l_path.exists():
        l_path.touch()
        _try_chmod(l_path, 0o444)
        if _tmp_case(case_dir):
            _legacy_case_path(case_dir, _LEDGER_FILE).touch()
            _try_chmod(_legacy_case_path(case_dir, _LEDGER_FILE), 0o444)


# ---------------------------------------------------------------------------
# Load helpers
# ---------------------------------------------------------------------------

def load_manifest(case_dir: Path) -> dict | None:
    path = manifest_path(case_dir)
    if _tmp_case(case_dir) and _legacy_case_path(case_dir, _MANIFEST_FILE).exists():
        path = _legacy_case_path(case_dir, _MANIFEST_FILE)
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text())
    except (json.JSONDecodeError, OSError):
        return None


def load_ledger(case_dir: Path) -> list[dict]:
    path = ledger_path(case_dir)
    if _tmp_case(case_dir) and _legacy_case_path(case_dir, _LEDGER_FILE).exists():
        path = _legacy_case_path(case_dir, _LEDGER_FILE)
    if not path.exists():
        return []
    events = []
    for line in path.read_text().splitlines():
        line = line.strip()
        if line:
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return events


# ---------------------------------------------------------------------------
# Hashing
# ---------------------------------------------------------------------------

def hash_file(path: Path) -> str:
    """Streaming SHA-256 of a file. Returns hex string."""
    sha = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            sha.update(chunk)
    return sha.hexdigest()


def compute_manifest_hash(manifest: dict) -> str:
    """SHA-256 of canonical manifest JSON with manifest_hash excluded.

    Returns 'sha256:<hex>'. Deterministic: same manifest → same hash.
    """
    hashable = {k: v for k, v in manifest.items() if k != "manifest_hash"}
    canonical = json.dumps(hashable, sort_keys=True, separators=(",", ":"), default=str)
    return "sha256:" + hashlib.sha256(canonical.encode()).hexdigest()


def _hmac_event(event: dict, derived_key: bytes) -> str:
    """HMAC-SHA256 of canonical event JSON with 'hmac' field excluded."""
    signable = {k: v for k, v in event.items() if k != "hmac"}
    canonical = json.dumps(signable, sort_keys=True, separators=(",", ":"), default=str)
    return hmac.new(derived_key, canonical.encode(), hashlib.sha256).hexdigest()


# ---------------------------------------------------------------------------
# Path validation
# ---------------------------------------------------------------------------

def _resolve_evidence_path(case_dir: Path, rel_path: str) -> Path:
    """Resolve a relative path, blocking symlink escapes outside evidence/.

    rel_path must be relative to case_dir and resolve under case_dir/evidence/.
    Raises ValueError on path traversal or symlink escape.
    """
    evidence_root = case_dir.resolve() / _EVIDENCE_SUBDIR
    candidate = (case_dir / rel_path).resolve()
    # Must be strictly inside evidence_root (not equal to it — dirs not registered)
    if not str(candidate).startswith(str(evidence_root) + os.sep):
        raise ValueError(
            f"Path {rel_path!r} resolves outside evidence directory: {candidate}"
        )
    return candidate


# ---------------------------------------------------------------------------
# Directory scanning
# ---------------------------------------------------------------------------

def scan_evidence_dir(case_dir: Path) -> list[dict]:
    """Walk evidence/ and return all regular files (not symlinks).

    Returns list of {path (relative to case_dir), bytes, mtime_ns}.
    mtime_ns is informational only — not used in integrity checks.
    """
    evidence_root = case_dir / _EVIDENCE_SUBDIR
    if not evidence_root.is_dir():
        return []
    results = []
    for p in sorted(evidence_root.rglob("*")):
        if p.is_symlink() or not p.is_file():
            continue
        try:
            st = p.stat()
        except OSError:
            continue
        results.append({
            "path": str(p.relative_to(case_dir)),
            "bytes": st.st_size,
            "mtime_ns": st.st_mtime_ns,
        })
    return results


# ---------------------------------------------------------------------------
# Diff (stat-check only — no rehash)
# ---------------------------------------------------------------------------

def diff_manifest(case_dir: Path, manifest: dict) -> dict:
    """Compare live evidence/ tree against sealed manifest (stat-check, no rehash).

    Ignores IGNORED entries. Size mismatch → MODIFIED (not MISSING).
    Returns {status, ok, missing, modified, unregistered}.
    """
    excluded = {
        f["path"]
        for f in manifest.get("files", [])
        if f.get("status") in ("IGNORED", "RETIRED")
    }
    registered = {
        f["path"]: f
        for f in manifest.get("files", [])
        if f.get("status") not in ("IGNORED", "RETIRED")
    }
    live = {f["path"]: f for f in scan_evidence_dir(case_dir)}

    ok: list[str] = []
    missing: list[str] = []
    modified: list[str] = []
    unregistered: list[str] = []

    for rel_path, reg in registered.items():
        if rel_path not in live:
            missing.append(rel_path)
        elif live[rel_path]["bytes"] != reg.get("bytes", -1):
            modified.append(rel_path)
        else:
            ok.append(rel_path)

    for rel_path in live:
        if rel_path not in registered and rel_path not in excluded:
            unregistered.append(rel_path)

    if missing:
        status = ChainStatus.MISSING
    elif modified:
        status = ChainStatus.MODIFIED
    elif unregistered:
        status = ChainStatus.UNREGISTERED
    else:
        status = ChainStatus.OK

    return {
        "status": status,
        "ok": ok,
        "missing": missing,
        "modified": modified,
        "unregistered": unregistered,
    }


# ---------------------------------------------------------------------------
# Gateway-safe status check (no key, no rehash)
# ---------------------------------------------------------------------------

def chain_status(case_dir: Path) -> dict:
    """Fast evidence chain status for the gateway.

    No key required. No file rehashing. Uses stat-check + structural hash-chain verify.
    Returns {status, issues, manifest_version, ok_count}.
    """
    manifest = load_manifest(case_dir)
    if manifest is None or (manifest.get("version", 0) == 0 and not manifest.get("files")):
        return {
            "status": ChainStatus.UNSEALED,
            "issues": ["No sealed evidence manifest"],
            "manifest_version": 0,
            "ok_count": 0,
        }

    # Structural: manifest hash
    stored = manifest.get("manifest_hash", "")
    computed = compute_manifest_hash(manifest)
    if stored and not hmac.compare_digest(stored, computed):
        return {
            "status": ChainStatus.LEDGER_ERROR,
            "issues": ["Manifest hash mismatch — manifest may have been tampered"],
            "manifest_version": manifest.get("version", 0),
            "ok_count": 0,
        }

    # Structural: ledger hash-chain
    ledger = load_ledger(case_dir)
    chain_err = _check_hash_chain(manifest, ledger)
    if chain_err:
        return {
            "status": ChainStatus.LEDGER_ERROR,
            "issues": [chain_err],
            "manifest_version": manifest.get("version", 0),
            "ok_count": 0,
        }

    # Stat-check
    diff = diff_manifest(case_dir, manifest)
    issues = (
        [f"Missing: {p}" for p in diff["missing"]]
        + [f"Modified: {p}" for p in diff["modified"]]
        + [f"Unregistered: {p}" for p in diff["unregistered"]]
    )
    return {
        "status": diff["status"],
        "issues": issues,
        "manifest_version": manifest.get("version", 0),
        "ok_count": len(diff["ok"]),
    }


def _check_hash_chain(manifest: dict, ledger: list[dict]) -> str | None:
    """Return error string if hash-chain is broken, None if OK.

    One event per manifest version: latest event's new_manifest_hash must match manifest.
    Consecutive events must link previous→new correctly.
    """
    if not ledger:
        return None

    latest = ledger[-1]
    current_hash = manifest.get("manifest_hash", "")
    latest_new = latest.get("new_manifest_hash", "")
    if current_hash and latest_new and not hmac.compare_digest(current_hash, latest_new):
        return "Latest ledger event new_manifest_hash does not match current manifest"

    for i in range(1, len(ledger)):
        prev_new = ledger[i - 1].get("new_manifest_hash", "")
        this_prev = ledger[i].get("previous_manifest_hash", "")
        if prev_new and this_prev and not hmac.compare_digest(prev_new, this_prev):
            return f"Hash-chain broken between ledger events {i - 1} and {i}"

    return None


# ---------------------------------------------------------------------------
# Full structural verify (no key) — portal "Verify integrity" button
# ---------------------------------------------------------------------------

def verify_chain_integrity(case_dir: Path) -> dict:
    """Structural verification: manifest hash + ledger hash-chain. No key needed."""
    manifest = load_manifest(case_dir)
    if manifest is None:
        return {"ok": False, "error": "No evidence manifest found"}

    computed = compute_manifest_hash(manifest)
    stored = manifest.get("manifest_hash", "")
    if stored and not hmac.compare_digest(stored, computed):
        return {"ok": False, "error": "Manifest hash mismatch"}

    ledger = load_ledger(case_dir)
    chain_err = _check_hash_chain(manifest, ledger)
    if chain_err:
        return {"ok": False, "error": chain_err}

    return {
        "ok": True,
        "version": manifest.get("version", 0),
        "events": len(ledger),
    }


# ---------------------------------------------------------------------------
# HMAC verify (portal only — requires derived_key)
# ---------------------------------------------------------------------------

def verify_chain_hmac(case_dir: Path, derived_key: bytes) -> dict:
    """Verify HMAC signature on every ledger event.

    Portal-only. Requires the examiner-derived key.
    Returns {ok, verified, failed, failed_indices}.
    """
    ledger = load_ledger(case_dir)
    if not ledger:
        return {"ok": True, "verified": 0, "failed": 0, "failed_indices": []}

    verified = 0
    failed = 0
    failed_indices: list[int] = []

    for i, event in enumerate(ledger):
        stored = event.get("hmac", "")
        expected = _hmac_event(event, derived_key)
        if stored and hmac.compare_digest(stored, expected):
            verified += 1
        else:
            failed += 1
            failed_indices.append(i)

    return {
        "ok": failed == 0,
        "verified": verified,
        "failed": failed,
        "failed_indices": failed_indices,
    }


# ---------------------------------------------------------------------------
# Seal (portal only — full SHA-256 rehash of new files)
# ---------------------------------------------------------------------------

def seal_manifest(
    case_dir: Path,
    file_specs: list[dict],
    examiner: str,
    derived_key: bytes,
    *,
    existing_manifest: dict | None = None,
) -> dict:
    """Seal a new evidence manifest version.

    file_specs: list of {path (relative to case_dir), source?, description?}.
    Hashes each specified file. Preserves IGNORED entries from previous manifest.
    Emits one MANIFEST_SEALED ledger event for the new version.
    Returns the new manifest dict.
    """
    if existing_manifest is None:
        existing_manifest = load_manifest(case_dir) or {
            "version": 0,
            "case_id": _load_case_id(case_dir),
            "manifest_hash": "",
            "files": [],
        }

    prev_hash = existing_manifest.get("manifest_hash", "")
    prev_version = existing_manifest.get("version", 0)
    case_id = existing_manifest.get("case_id", "") or _load_case_id(case_dir)
    now = _now()

    # Carry forward IGNORED, RETIRED, and ACTIVE entries not being explicitly re-registered.
    # The portal only sends newly-unregistered files in file_specs, so previously ACTIVE
    # entries must be preserved here or they silently disappear from the manifest.
    file_spec_paths = {spec["path"] for spec in file_specs}
    carried = [
        f for f in existing_manifest.get("files", [])
        if f.get("status") in ("IGNORED", "RETIRED")
        or (f.get("status") == "ACTIVE" and f.get("path") not in file_spec_paths)
    ]

    new_files = list(carried)
    for spec in file_specs:
        rel_path = spec["path"]
        abs_path = _resolve_evidence_path(case_dir, rel_path)
        if not abs_path.exists():
            raise FileNotFoundError(f"Evidence file not found: {rel_path}")
        if abs_path.is_dir():
            raise ValueError(f"Cannot register directory: {rel_path}")

        # Clear immutable flag before hashing (no-op if already clear or cap absent)
        _set_immutable(abs_path, False)

        st = abs_path.stat()
        file_hash = hash_file(abs_path)

        new_files.append({
            "path": rel_path,
            "sha256": file_hash,
            "bytes": st.st_size,
            "mtime_ns": st.st_mtime_ns,
            "registered_at": now,
            "registered_by": examiner,
            "source": spec.get("source", ""),
            "description": spec.get("description", ""),
            "status": "ACTIVE",
        })

    new_manifest: dict = {
        "version": prev_version + 1,
        "case_id": case_id,
        "created_at": now,
        "created_by": examiner,
        "previous_manifest_hash": prev_hash,
        "manifest_hash": "",
        "files": new_files,
    }
    new_hash = compute_manifest_hash(new_manifest)
    new_manifest["manifest_hash"] = new_hash

    _atomic_write_json_with_tmp_shadow(case_dir, manifest_path(case_dir), new_manifest, _MANIFEST_FILE)

    event: dict = {
        "event": "MANIFEST_SEALED",
        "case_id": case_id,
        "version": new_manifest["version"],
        "files_added": [s["path"] for s in file_specs],
        "previous_manifest_hash": prev_hash,
        "new_manifest_hash": new_hash,
        "approved_by": examiner,
        "approved_at": now,
        "hmac_version": 1,
    }
    _append_ledger_event(ledger_path(case_dir), event, derived_key)
    if _tmp_case(case_dir):
        _append_ledger_event(_legacy_case_path(case_dir, _LEDGER_FILE), event, derived_key)

    # Set immutable flag on each newly registered file (Phase 17a)
    for spec in file_specs:
        abs_path = case_dir / spec["path"]
        if abs_path.exists():
            if not _set_immutable(abs_path, True):
                logger.warning(
                    "seal_manifest: could not set +i on %s "
                    "(install.sh setcap step may not have run)", abs_path
                )

    return new_manifest


def ignore_file(
    case_dir: Path,
    rel_path: str,
    examiner: str,
    derived_key: bytes,
    reason: str,
) -> None:
    """Record a FILE_IGNORED decision for an unregistered evidence file.

    Creates a new manifest version with the file marked IGNORED.
    The file is not hashed — only its path and the examiner's reason are recorded.
    """
    _resolve_evidence_path(case_dir, rel_path)  # raises ValueError on traversal

    manifest = load_manifest(case_dir)
    if manifest is None:
        raise ValueError("No evidence manifest — call init_evidence_chain first")

    prev_hash = manifest.get("manifest_hash", "")
    prev_version = manifest.get("version", 0)
    case_id = manifest.get("case_id", "") or _load_case_id(case_dir)
    now = _now()

    files = list(manifest.get("files", []))
    files.append({
        "path": rel_path,
        "sha256": "",
        "bytes": 0,
        "mtime_ns": 0,
        "registered_at": now,
        "registered_by": examiner,
        "source": "",
        "description": reason,
        "status": "IGNORED",
    })

    new_manifest: dict = {
        "version": prev_version + 1,
        "case_id": case_id,
        "created_at": now,
        "created_by": examiner,
        "previous_manifest_hash": prev_hash,
        "manifest_hash": "",
        "files": files,
    }
    new_hash = compute_manifest_hash(new_manifest)
    new_manifest["manifest_hash"] = new_hash

    _atomic_write_json_with_tmp_shadow(case_dir, manifest_path(case_dir), new_manifest, _MANIFEST_FILE)

    event: dict = {
        "event": "FILE_IGNORED",
        "case_id": case_id,
        "version": new_manifest["version"],
        "path": rel_path,
        "reason": reason,
        "previous_manifest_hash": prev_hash,
        "new_manifest_hash": new_hash,
        "approved_by": examiner,
        "approved_at": now,
        "hmac_version": 1,
    }
    _append_ledger_event(ledger_path(case_dir), event, derived_key)
    if _tmp_case(case_dir):
        _append_ledger_event(_legacy_case_path(case_dir, _LEDGER_FILE), event, derived_key)


# ---------------------------------------------------------------------------
# Retire (portal only — requires derived_key)
# ---------------------------------------------------------------------------

def retire_file(
    case_dir: Path,
    rel_path: str,
    reason: str,
    examiner: str,
    derived_key: bytes,
) -> None:
    """Record the deliberate removal of a registered evidence file.

    The file must be ACTIVE in the current manifest. Clears the immutable
    flag so the caller can delete the file from disk afterwards.
    Creates a new manifest version with the file marked RETIRED and appends
    a FILE_RETIRED ledger event (HMAC-signed). Does NOT delete the file —
    the caller (portal route) is responsible for the actual unlink.

    Raises ValueError if:
    - No evidence manifest exists
    - rel_path is not registered (ACTIVE) in the current manifest
    """
    manifest = load_manifest(case_dir)
    if manifest is None:
        raise ValueError("No evidence manifest — call init_evidence_chain first")

    files = list(manifest.get("files", []))

    # Find the ACTIVE entry for this path
    active_index = None
    for i, f in enumerate(files):
        if f["path"] == rel_path:
            if f.get("status") == "IGNORED":
                raise ValueError(
                    f"Cannot retire IGNORED file {rel_path!r} — "
                    "use ignore_file() only for unregistered files"
                )
            if f.get("status") == "RETIRED":
                raise ValueError(f"File {rel_path!r} is already RETIRED")
            active_index = i
            break

    if active_index is None:
        raise ValueError(
            f"File {rel_path!r} is not registered in the evidence manifest"
        )

    # Clear immutable flag so the caller can remove the file
    abs_path = case_dir / rel_path
    if abs_path.exists():
        if not _set_immutable(abs_path, False):
            logger.warning("retire_file: could not clear immutable flag on %s", abs_path)

    prev_hash = manifest.get("manifest_hash", "")
    prev_version = manifest.get("version", 0)
    case_id = manifest.get("case_id", "") or _load_case_id(case_dir)
    now = _now()

    # Replace ACTIVE entry with RETIRED
    files[active_index] = {
        **files[active_index],
        "status": "RETIRED",
        "retired_at": now,
        "retired_by": examiner,
        "retire_reason": reason,
    }

    new_manifest: dict = {
        "version": prev_version + 1,
        "case_id": case_id,
        "created_at": now,
        "created_by": examiner,
        "previous_manifest_hash": prev_hash,
        "manifest_hash": "",
        "files": files,
    }
    new_hash = compute_manifest_hash(new_manifest)
    new_manifest["manifest_hash"] = new_hash

    _atomic_write_json_with_tmp_shadow(case_dir, manifest_path(case_dir), new_manifest, _MANIFEST_FILE)

    event: dict = {
        "event": "FILE_RETIRED",
        "case_id": case_id,
        "version": new_manifest["version"],
        "path": rel_path,
        "reason": reason,
        "previous_manifest_hash": prev_hash,
        "new_manifest_hash": new_hash,
        "approved_by": examiner,
        "approved_at": now,
        "hmac_version": 1,
    }
    _append_ledger_event(ledger_path(case_dir), event, derived_key)
    if _tmp_case(case_dir):
        _append_ledger_event(_legacy_case_path(case_dir, _LEDGER_FILE), event, derived_key)


# ---------------------------------------------------------------------------
# Immutable flag helper (Phase 17a — graceful fallback)
# ---------------------------------------------------------------------------

_FS_IOC_GETFLAGS = 0x80086601
_FS_IOC_SETFLAGS = 0x40086602
_FS_IMMUTABLE_FL = 0x00000010


def _set_immutable(path: Path, immutable: bool) -> bool:
    """Set or clear the immutable flag on a file (Linux ext4/XFS/btrfs).

    Requires CAP_LINUX_IMMUTABLE. Returns True on success, False on EPERM
    or any OS error — does not raise. Caller logs a warning on False.
    No-op and returns False on non-Linux or unsupported filesystem.
    """
    try:
        flags_val = ctypes.c_int(0)
        with open(path, "rb") as f:
            fcntl.ioctl(f.fileno(), _FS_IOC_GETFLAGS, flags_val)
        if immutable:
            flags_val.value |= _FS_IMMUTABLE_FL
        else:
            flags_val.value &= ~_FS_IMMUTABLE_FL
        with open(path, "rb") as f:
            fcntl.ioctl(f.fileno(), _FS_IOC_SETFLAGS, flags_val)
        return True
    except (OSError, IOError, AttributeError):
        return False


def get_immutable_flag(path: Path) -> bool | None:
    """Return True if the immutable flag is set, False if clear, None on error.

    Public helper for portal status display (Phase 17a).
    """
    try:
        flags_val = ctypes.c_int(0)
        with open(path, "rb") as f:
            fcntl.ioctl(f.fileno(), _FS_IOC_GETFLAGS, flags_val)
        return bool(flags_val.value & _FS_IMMUTABLE_FL)
    except (OSError, IOError, AttributeError):
        return None


# ---------------------------------------------------------------------------
# Sealed-evidence filesystem hardening (B-MVP-048)
# ---------------------------------------------------------------------------
#
# On seal, evidence bytes must carry the immutable flag (FS_IMMUTABLE_FL). The
# runtime user is the NON-root service account, but install.sh grants the venv
# interpreter CAP_LINUX_IMMUTABLE (configure_immutable_capability), so the
# gateway can set AND clear +i IN-PROCESS even on a root:root world-readable
# (0644) file. +i is the load-bearing, owner-independent integrity property: no
# one — not even root — can modify, delete, or rename the file until +i is
# cleared. There is deliberately NO chown and NO privileged helper: re-owning
# bytes to the service user added a privileged attack surface for negative value
# (root:root 0644 means the gateway can read but is not the owner — tighter).
# Ownership is reported informationally only and never gates the seal.
#
# Every path is re-resolved here and proven to be a regular file strictly inside
# the active case's evidence/ dir, with symlinks rejected: this is a privileged
# operation, so the input is treated as hostile even though the caller is trusted.


def _resolve_sealed_target(case_dir: Path, rel_path: str) -> Path:
    """Resolve a path to a regular evidence file, hostile-input safe.

    Reuses _resolve_evidence_path (blocks traversal/symlink escape via resolve),
    then additionally rejects a final symlink and any non-regular file. Returns
    the fully resolved absolute path.
    """
    # Reject a symlink at the literal (unresolved) target before following it:
    # _resolve_evidence_path .resolve()s the path, which would hide a symlink by
    # returning its destination. A privileged chattr/chown must never act through
    # a symlink the operator (or anything) planted in evidence/.
    literal = case_dir / rel_path
    if literal.is_symlink():
        raise EvidenceHardeningError(f"Refusing to harden a symlink: {rel_path!r}")
    abs_path = _resolve_evidence_path(case_dir, rel_path)
    if abs_path.is_symlink():  # pragma: no cover - resolve() removes symlinks
        raise EvidenceHardeningError(f"Refusing to harden a symlink: {rel_path!r}")
    if not abs_path.exists():
        raise EvidenceHardeningError(f"Evidence file not found for hardening: {rel_path!r}")
    if abs_path.is_dir() or not abs_path.is_file():
        raise EvidenceHardeningError(f"Not a regular evidence file: {rel_path!r}")
    return abs_path


def _file_owner_name(path: Path) -> str | None:
    try:
        return pwd.getpwuid(path.stat().st_uid).pw_name
    except (KeyError, OSError):
        return None


def harden_sealed_evidence(
    case_dir: Path,
    rel_paths: list[str],
    *,
    service_user: str = DEFAULT_SERVICE_USER,
) -> list[dict]:
    """Set the immutable flag (+i) IN-PROCESS on each sealed evidence file.

    For each path (relative to ``case_dir``, resolving strictly inside
    ``evidence/``), set FS_IMMUTABLE_FL via the in-process ioctl helper. NO
    chown, NO privileged helper: the venv interpreter carries
    CAP_LINUX_IMMUTABLE (install.sh configure_immutable_capability), so +i works
    in-process even on a root:root world-readable (0644) file.

    Fails CLOSED:
      * any path that cannot be resolved to a regular evidence file -> raise.
      * immutable flag cannot be set, or is absent after setting -> raise (this
        is the load-bearing integrity property).

    ``service_user`` is accepted for caller compatibility but ownership is never
    enforced; the immutable flag protects the bytes regardless of owner. Owner is
    reported informationally (best-effort) and never raises.

    Returns one ``{path, immutable, owner}`` dict per input path.
    """
    results: list[dict] = []
    for rel_path in rel_paths:
        abs_path = _resolve_sealed_target(case_dir, rel_path)

        if not _set_immutable(abs_path, True):
            raise EvidenceHardeningError(
                f"Could not set the immutable flag on sealed evidence {rel_path!r}. "
                "The interpreter must carry CAP_LINUX_IMMUTABLE (install.sh "
                "configure_immutable_capability). The seal was NOT hardened on disk."
            )

        immutable = get_immutable_flag(abs_path)
        if not immutable:
            raise EvidenceHardeningError(
                f"Immutable flag is not present on sealed evidence {rel_path!r} "
                "after hardening; refusing to report a hardened seal."
            )

        owner = _file_owner_name(abs_path)
        if owner != service_user:
            logger.info(
                "harden_sealed_evidence: %s is owned by %s (not %s); immutable flag "
                "applied. Ownership is informational only and not enforced.",
                abs_path,
                owner,
                service_user,
            )

        results.append({"path": rel_path, "immutable": True, "owner": owner})
    return results


def unharden_sealed_evidence(case_dir: Path, rel_paths: list[str]) -> list[dict]:
    """Clear the immutable flag (-i) IN-PROCESS on each sealed evidence file.

    Makes the bytes mutable again so the operator can replace/re-image evidence.
    Uses the same strict path resolution as :func:`harden_sealed_evidence`
    (resolves strictly inside ``evidence/``, rejects symlinks and non-regular
    files).

    Idempotent: a file whose flag is already clear is success. Fails CLOSED —
    raises :class:`EvidenceHardeningError` if the immutable flag is STILL PRESENT
    after attempting to clear it.

    Returns one ``{path, immutable}`` dict per input path (``immutable`` always
    ``False`` on success).
    """
    results: list[dict] = []
    for rel_path in rel_paths:
        abs_path = _resolve_sealed_target(case_dir, rel_path)

        # _set_immutable returning False can mean either an OS error or that the
        # cap is absent. Do not raise on its return value alone; instead verify
        # the resulting flag state, which is the authoritative check (idempotent:
        # an already-clear file is fine even if the ioctl reports no change).
        _set_immutable(abs_path, False)

        if get_immutable_flag(abs_path):
            raise EvidenceHardeningError(
                f"Immutable flag is STILL PRESENT on sealed evidence {rel_path!r} "
                "after attempting to clear it. The interpreter must carry "
                "CAP_LINUX_IMMUTABLE (install.sh configure_immutable_capability). "
                "The evidence was NOT made mutable on disk."
            )

        results.append({"path": rel_path, "immutable": False})
    return results


# ---------------------------------------------------------------------------
# Ledger append (internal)
# ---------------------------------------------------------------------------

def _append_ledger_event(ledger_path: Path, event: dict, derived_key: bytes) -> None:
    event["hmac"] = _hmac_event(event, derived_key)
    _try_chmod(ledger_path, 0o644)
    with open(ledger_path, "a") as f:
        f.write(json.dumps(event, separators=(",", ":"), default=str) + "\n")
        f.flush()
        os.fsync(f.fileno())
    _try_chmod(ledger_path, 0o444)


# ---------------------------------------------------------------------------
# Solana anchoring (Phase 16e — optional, degrades gracefully without solders)
# ---------------------------------------------------------------------------

_ANCHOR_PROOF_PATTERN = "evidence-anchor-v{version}.json"
_MEMO_PROGRAM_ID = "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr"
_SOLANA_MAINNET_RPC = "https://api.mainnet-beta.solana.com"
_SOLANA_DEVNET_RPC = "https://api.devnet.solana.com"


def load_anchor_proof(case_dir: Path, version: int) -> dict | None:
    """Load evidence-anchor-v{N}.json. Returns None if not present."""
    path = anchor_proof_path(case_dir, version)
    if _tmp_case(case_dir) and _legacy_case_path(case_dir, _ANCHOR_PROOF_PATTERN.format(version=version)).exists():
        path = _legacy_case_path(case_dir, _ANCHOR_PROOF_PATTERN.format(version=version))
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text())
    except (json.JSONDecodeError, OSError):
        return None


def anchor_manifest(
    case_dir: Path,
    manifest: dict,
    ledger: list[dict],
    *,
    keypair_path: str | None = None,
    rpc_url: str | None = None,
    cluster: str = "mainnet",
) -> dict:
    """Anchor the manifest hash on Solana via SPL Memo. Degrades gracefully without solders.

    Writes evidence-anchor-v{N}.json to the case records dir. Returns the proof dict.
    If keypair_path is None or solders is not installed, the proof is written
    with solana_tx=None (unanchored but locally recorded).
    """
    version = manifest.get("version", 0)
    manifest_hash = manifest.get("manifest_hash", "")
    ledger_tip_hmac = ledger[-1].get("hmac", "") if ledger else ""

    mh_hex = manifest_hash.split(":")[-1] if ":" in manifest_hash else manifest_hash
    anchor_payload = f"SIFT|{mh_hex[:16]}|{ledger_tip_hmac[:16]}"

    proof: dict = {
        "schema": "sift.evidence-anchor.v1",
        "timestamp": _now(),
        "manifest_version": version,
        "manifest_hash": manifest_hash,
        "ledger_tip_hmac": ledger_tip_hmac,
        "anchor_payload": anchor_payload,
        "solana_tx": None,
        "solana_cluster": cluster,
        "confirmed": False,
        "explorer_url": None,
    }

    if keypair_path:
        try:
            _do_solana_anchor(proof, keypair_path, rpc_url, cluster)
        except ImportError:
            logger.warning("anchor_manifest: solders not installed — proof written without on-chain tx")
        except Exception as exc:
            logger.warning("anchor_manifest: Solana submission failed: %s", exc)

    proof_path = anchor_proof_path(case_dir, version)
    _atomic_write_json_with_tmp_shadow(
        case_dir,
        proof_path,
        proof,
        _ANCHOR_PROOF_PATTERN.format(version=version),
    )
    return proof


def anchor_db_proof(
    *,
    manifest_version: int,
    manifest_hash: str,
    ledger_tip_hash: str,
    keypair_path: str | None = None,
    rpc_url: str | None = None,
    cluster: str = "mainnet",
) -> dict:
    """Anchor DB-derived proof material on Solana without writing any case file.

    The payload is derived from DB custody authority (manifest hash + custody
    chain head/ledger tip + manifest version) supplied by the caller. Returns the
    proof dict; the DB-active caller records it in app.evidence_proof_exports.
    Degrades gracefully: if no keypair is configured or solders is unavailable,
    solana_tx stays None (proof material recorded, no on-chain tx). Anchoring is
    external proof only and never decides evidence gate state.
    """
    mh_hex = manifest_hash.split(":")[-1] if ":" in manifest_hash else manifest_hash
    tip_hex = ledger_tip_hash.split(":")[-1] if ":" in ledger_tip_hash else ledger_tip_hash
    anchor_payload = f"SIFT|{mh_hex[:16]}|{tip_hex[:16]}"

    proof: dict = {
        "schema": "sift.evidence-anchor.v1",
        "timestamp": _now(),
        "manifest_version": manifest_version,
        "manifest_hash": manifest_hash,
        "ledger_tip_hmac": ledger_tip_hash,
        "anchor_payload": anchor_payload,
        "solana_tx": None,
        "solana_cluster": cluster,
        "confirmed": False,
        "explorer_url": None,
    }

    if keypair_path:
        try:
            _do_solana_anchor(proof, keypair_path, rpc_url, cluster)
        except ImportError:
            logger.warning("anchor_db_proof: solders not installed — proof recorded without on-chain tx")
        except Exception as exc:
            logger.warning("anchor_db_proof: Solana submission failed: %s", exc)

    return proof


def _do_solana_anchor(proof: dict, keypair_path: str, rpc_url: str | None, cluster: str) -> None:
    """Submit anchor_payload to Solana via SPL Memo. Modifies proof in place."""
    import base64
    import time as _time
    from solders.keypair import Keypair
    from solders.pubkey import Pubkey
    from solders.transaction import Transaction
    from solders.message import Message
    from solders.instruction import Instruction, AccountMeta
    from solders.hash import Hash as SolHash

    rpc = rpc_url or (_SOLANA_MAINNET_RPC if cluster == "mainnet" else _SOLANA_DEVNET_RPC)

    kp_data = json.loads(Path(keypair_path).expanduser().read_text())
    keypair = Keypair.from_bytes(bytes(kp_data))

    memo_data = proof["anchor_payload"].encode("utf-8")
    memo_program = Pubkey.from_string(_MEMO_PROGRAM_ID)
    memo_ix = Instruction(
        program_id=memo_program,
        accounts=[AccountMeta(pubkey=keypair.pubkey(), is_signer=True, is_writable=False)],
        data=memo_data,
    )

    bh_resp = _rpc_call(rpc, "getLatestBlockhash", [{"commitment": "finalized"}])
    blockhash = SolHash.from_string(bh_resp["result"]["value"]["blockhash"])

    msg = Message.new_with_blockhash([memo_ix], keypair.pubkey(), blockhash)
    tx = Transaction.new_unsigned(msg)
    tx.sign([keypair], blockhash)

    tx_b64 = base64.b64encode(bytes(tx)).decode("utf-8")
    send_resp = _rpc_call(rpc, "sendTransaction", [tx_b64, {"encoding": "base64", "skipPreflight": False}])

    if "error" in send_resp:
        raise RuntimeError(f"Solana RPC error: {send_resp['error']}")

    tx_sig = send_resp["result"]

    _time.sleep(2)
    confirm_resp = _rpc_call(rpc, "getTransaction", [tx_sig, {"encoding": "json", "commitment": "confirmed"}])
    confirmed = confirm_resp.get("result") is not None

    explorer = (
        f"https://solscan.io/tx/{tx_sig}"
        if cluster == "mainnet"
        else f"https://solscan.io/tx/{tx_sig}?cluster=devnet"
    )
    proof["solana_tx"] = tx_sig
    proof["confirmed"] = confirmed
    proof["explorer_url"] = explorer


def _rpc_call(url: str, method: str, params: list) -> dict:
    import json as _json
    import urllib.request as _urlib
    payload = _json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode()
    req = _urlib.Request(url, data=payload, headers={"Content-Type": "application/json"})
    with _urlib.urlopen(req, timeout=30) as resp:
        return _json.loads(resp.read())


# ---------------------------------------------------------------------------
# Internal utilities
# ---------------------------------------------------------------------------

def _atomic_write_json(path: Path, data: dict) -> None:
    content = json.dumps(data, indent=2, default=str)
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), suffix=".tmp")
    try:
        with os.fdopen(fd, "w") as f:
            f.write(content)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, str(path))
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def _try_chmod(path: Path, mode: int) -> None:
    try:
        os.chmod(path, mode)
    except OSError:
        pass


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _load_case_id(case_dir: Path) -> str:
    meta = case_dir / "CASE.yaml"
    if not meta.exists():
        return ""
    try:
        import yaml
        return (yaml.safe_load(meta.read_text()) or {}).get("case_id", "")
    except Exception:
        return ""
