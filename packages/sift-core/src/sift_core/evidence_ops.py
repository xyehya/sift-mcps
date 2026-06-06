"""Evidence management data functions.

Pure-data layer (no CLI output). Used by the core evidence tools.
"""

from __future__ import annotations

import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path

from sift_core.case_io import _atomic_write
from sift_core.evidence_chain import ChainStatus, chain_status, load_manifest


def register_evidence_data(
    case_dir, path: str, examiner: str, description: str = ""
) -> dict:
    """Register an evidence file. Returns entry dict."""
    case_dir = Path(case_dir)
    evidence_path = Path(path)

    if not evidence_path.is_absolute():
        evidence_path = case_dir / evidence_path

    if not evidence_path.exists():
        raise FileNotFoundError(f"File not found: {path}")

    if evidence_path.is_dir():
        raise ValueError(
            f"'{path}' is a directory. Register individual files or a container archive."
        )

    # Ensure path is within case directory
    resolved = evidence_path.resolve()
    case_resolved = case_dir.resolve()
    in_case = (
        str(resolved).startswith(str(case_resolved) + os.sep)
        or resolved == case_resolved
    )
    if not in_case:
        evidence_path_abs = (
            evidence_path if evidence_path.is_absolute() else case_dir / evidence_path
        )
        normalized = Path(os.path.normpath(evidence_path_abs))
        case_norm = Path(os.path.normpath(case_resolved))
        if not (
            str(normalized).startswith(str(case_norm) + os.sep)
            or normalized == case_norm
        ):
            raise ValueError(
                f"Evidence path must be within the case directory.\n"
                f"  Path:     {evidence_path}\n"
                f"  Resolved: {resolved}\n"
                f"  Case dir: {case_resolved}"
            )

    sha = hashlib.sha256()
    with open(evidence_path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            sha.update(chunk)
    file_hash = sha.hexdigest()

    reg_file = case_dir / "evidence.json"
    try:
        if reg_file.exists():
            registry = json.loads(reg_file.read_text())
        else:
            registry = {"files": []}
    except (json.JSONDecodeError, OSError):
        registry = {"files": []}

    for existing in registry.get("files", []):
        if existing.get("path") == str(resolved):
            if existing.get("sha256") == file_hash:
                return {**existing, "note": "already registered (same path and hash)"}
            else:
                existing["sha256"] = file_hash
                existing["registered_at"] = datetime.now(timezone.utc).isoformat()
                existing["registered_by"] = examiner
                if description:
                    existing["description"] = description
                _atomic_write(reg_file, json.dumps(registry, indent=2, default=str))
                return {**existing, "note": "updated (same path, hash changed)"}

    entry = {
        "path": str(resolved),
        "sha256": file_hash,
        "description": description,
        "registered_at": datetime.now(timezone.utc).isoformat(),
        "registered_by": examiner,
    }
    registry["files"].append(entry)
    _atomic_write(reg_file, json.dumps(registry, indent=2, default=str))
    return entry


def list_evidence_data(case_dir) -> dict:
    """Return registered evidence as structured data."""
    case_dir = Path(case_dir)
    reg_file = case_dir / "evidence.json"
    if not reg_file.exists():
        return {"evidence": [], "registry_exists": False}
    registry = json.loads(reg_file.read_text())
    return {"evidence": registry.get("files", []), "registry_exists": True}


def list_manifest_evidence_data(case_dir) -> dict:
    """Return sealed evidence manifest entries as structured data."""
    case_dir = Path(case_dir)
    manifest = load_manifest(case_dir)
    if manifest is None:
        return {"evidence": [], "registry_exists": False, "manifest_version": 0}
    active_files = [
        f for f in manifest.get("files", []) if f.get("status") != "IGNORED"
    ]
    return {
        "evidence": active_files,
        "registry_exists": True,
        "manifest_version": manifest.get("version", 0),
    }


def list_evidence_status_data(case_dir) -> dict:
    """Return sealed and unregistered evidence with inline chain status."""
    case_dir = Path(case_dir)
    evidence_data = list_manifest_evidence_data(case_dir)
    active_files = evidence_data["evidence"]
    manifest_version = evidence_data["manifest_version"]
    manifest_exists = evidence_data["registry_exists"]

    try:
        cs = chain_status(case_dir)
        chain = {
            "status": cs["status"],
            "ok_count": cs["ok_count"],
            "issues": cs["issues"],
        }
    except Exception:
        chain = {
            "status": "unknown",
            "ok_count": 0,
            "issues": ["Chain status check failed — call evidence_info for details."],
        }

    evidence_dir = case_dir / "evidence"
    registered_paths = {f.get("path", "") for f in active_files}
    unregistered = []
    if evidence_dir.is_dir():
        for f in sorted(evidence_dir.rglob("*")):
            if not f.is_file():
                continue
            rel = str(f.relative_to(case_dir))
            if rel not in registered_paths and str(f) not in registered_paths:
                unregistered.append(
                    {
                        "path": rel,
                        "size_bytes": f.stat().st_size,
                        "registered": False,
                        "action_required": (
                            "Notify the operator to seal this file via "
                            "Examiner Portal → Evidence tab before analysis."
                        ),
                    }
                )

    has_chain_issues = bool(
        chain.get("issues")
        and chain.get("status") not in (ChainStatus.OK, ChainStatus.UNSEALED)
    )
    requires_examiner_action = bool(unregistered or has_chain_issues)

    result = {
        "evidence": active_files,
        "unregistered": unregistered,
        "chain": chain,
        "requires_examiner_action": requires_examiner_action,
        "manifest_version": manifest_version,
        "source": "manifest_v2",
    }
    if requires_examiner_action:
        hints = []
        if unregistered:
            hints.append(
                f"{len(unregistered)} unregistered file(s) found — "
                "operator must seal via portal before analysis."
            )
        if has_chain_issues:
            hints.append(
                "Chain integrity issues detected — call evidence_info "
                "for a full check before escalating to the operator."
            )
        result["examiner_action_hint"] = " ".join(hints)
    if not manifest_exists:
        result["note"] = "No evidence manifest — case not yet initialised via portal."
    return result


def verify_evidence_data(case_dir) -> dict:
    """Verify evidence integrity. Returns results dict with status per file."""
    case_dir = Path(case_dir)
    reg_file = case_dir / "evidence.json"

    if not reg_file.exists():
        return {"results": [], "verified": 0, "modified": 0, "missing": 0, "errors": 0}

    registry = json.loads(reg_file.read_text())
    files = registry.get("files", [])
    if not files:
        return {"results": [], "verified": 0, "modified": 0, "missing": 0, "errors": 0}

    results = []
    verified = modified = missing = errors = 0

    for entry in files:
        path = Path(entry.get("path", ""))
        expected_hash = entry.get("sha256", "")

        if not path.exists():
            results.append(
                {"path": str(path), "status": "MISSING", "expected_hash": expected_hash, "actual_hash": None}
            )
            missing += 1
            continue

        try:
            sha = hashlib.sha256()
            with open(path, "rb") as f:
                for chunk in iter(lambda: f.read(8192), b""):
                    sha.update(chunk)
            actual_hash = sha.hexdigest()
            if actual_hash == expected_hash:
                results.append({"path": str(path), "status": "OK", "expected_hash": expected_hash, "actual_hash": actual_hash})
                verified += 1
            else:
                results.append({"path": str(path), "status": "MODIFIED", "expected_hash": expected_hash, "actual_hash": actual_hash})
                modified += 1
        except OSError as e:
            results.append({"path": str(path), "status": "ERROR", "error": str(e)})
            errors += 1

    return {
        "results": results,
        "verified": verified,
        "modified": modified,
        "missing": missing,
        "errors": errors,
    }
