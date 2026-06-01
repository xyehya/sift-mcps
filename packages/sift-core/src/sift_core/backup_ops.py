"""Case backup data functions. Used by case-mcp backup_case tool."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
from datetime import datetime, timezone
from pathlib import Path

from sift_core.case_io import load_case_meta
from sift_core.verification import VERIFICATION_DIR

_SKIP_NAMES = {"__pycache__", ".DS_Store", "examiners.bak"}
_PASSWORDS_DIR = Path(os.environ.get("SIFT_PASSWORDS_DIR", "/var/lib/sift/passwords"))


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            chunk = f.read(65536)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def human_size(nbytes: int) -> str:
    if nbytes >= 1_000_000_000:
        return f"{nbytes / 1_000_000_000:.1f} GB"
    if nbytes >= 1_000_000:
        return f"{nbytes / 1_000_000:.1f} MB"
    if nbytes >= 1_000:
        return f"{nbytes / 1_000:.0f} KB"
    return f"{nbytes} B"


def scan_case_dir(case_dir: Path) -> dict:
    """Categorize files in case directory into case_data, evidence, extractions."""
    case_data = []
    evidence = []
    extractions = []
    symlinks = []

    for root, dirs, files in os.walk(case_dir, followlinks=True):
        dirs[:] = [d for d in dirs if d not in _SKIP_NAMES]
        root_path = Path(root)
        for fname in files:
            if fname in _SKIP_NAMES:
                continue
            abs_path = root_path / fname
            rel_path = abs_path.relative_to(case_dir)
            try:
                size = abs_path.stat().st_size
            except OSError:
                continue
            if abs_path.is_symlink():
                try:
                    target = str(abs_path.resolve())
                except OSError:
                    target = "(unresolvable)"
                symlinks.append((str(rel_path), target, size))
            entry = (str(rel_path), str(abs_path), size)
            parts = rel_path.parts
            if parts and parts[0] == "evidence":
                evidence.append(entry)
            elif parts and parts[0] == "extractions":
                extractions.append(entry)
            else:
                case_data.append(entry)

    return {"case_data": case_data, "evidence": evidence, "extractions": extractions, "symlinks": symlinks}


def create_backup_data(
    case_dir: Path,
    destination: str,
    examiner: str,
    *,
    include_evidence: bool = False,
    include_extractions: bool = False,
    include_opensearch: bool = False,
    purpose: str = "",
    progress_fn=None,
) -> dict:
    """Create a case backup. Returns result dict with backup_path, file_count, etc."""
    meta = load_case_meta(case_dir)
    case_id = meta.get("case_id", case_dir.name)
    dest = Path(destination)

    date_str = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    backup_name = f"{case_id}-{date_str}"
    backup_dir = dest / backup_name
    suffix = 0
    while True:
        try:
            backup_dir.mkdir(parents=True, exist_ok=False)
            break
        except FileExistsError:
            suffix += 1
            backup_dir = dest / f"{backup_name}-{suffix}"

    marker = backup_dir / ".backup-in-progress"
    marker.touch()

    scan = scan_case_dir(case_dir)
    files_to_copy = list(scan["case_data"])
    if include_evidence:
        files_to_copy.extend(scan["evidence"])
    if include_extractions:
        files_to_copy.extend(scan["extractions"])

    ledger_path = VERIFICATION_DIR / f"{case_id}.jsonl"
    ledger_included = False
    ledger_note = ""
    if ledger_path.is_file():
        try:
            vdir = backup_dir / "verification"
            vdir.mkdir(exist_ok=True)
            shutil.copy2(str(ledger_path), str(vdir / f"{case_id}.jsonl"))
            ledger_included = True
        except OSError:
            ledger_note = "Warning: could not copy verification ledger"
    else:
        ledger_note = "Note: no verification ledger found for this case"

    password_examiners: list[str] = []
    try:
        findings_file = case_dir / "findings.json"
        if findings_file.exists():
            findings = json.loads(findings_file.read_text())
            if isinstance(findings, list):
                examiners_in_case = {
                    f.get("created_by", "") for f in findings if f.get("created_by")
                }
                pw_dir = backup_dir / "passwords"
                for ex in sorted(examiners_in_case):
                    pw_file = _PASSWORDS_DIR / f"{ex}.json"
                    if pw_file.is_file():
                        pw_dir.mkdir(exist_ok=True)
                        shutil.copy2(str(pw_file), str(pw_dir / f"{ex}.json"))
                        password_examiners.append(ex)
    except (json.JSONDecodeError, OSError):
        pass

    total_files = len(files_to_copy)
    for i, (rel_path, abs_path, _size) in enumerate(files_to_copy, 1):
        dst = backup_dir / rel_path
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(str(abs_path), str(dst))
        if progress_fn:
            progress_fn("Copying", i, total_files)

    all_backup_files = []
    for root, _dirs, filenames in os.walk(backup_dir, followlinks=True):
        for fname in filenames:
            if fname == ".backup-in-progress":
                continue
            fpath = Path(root) / fname
            rel = fpath.relative_to(backup_dir)
            all_backup_files.append((str(rel), fpath))

    manifest_files = []
    total_bytes = 0
    total_manifest = len(all_backup_files)
    for i, (rel, fpath) in enumerate(sorted(all_backup_files), 1):
        fsize = fpath.stat().st_size
        fhash = sha256_file(fpath)
        manifest_files.append({"path": rel, "sha256": fhash, "bytes": fsize})
        total_bytes += fsize
        if progress_fn:
            progress_fn("Generating manifest", i, total_manifest)

    manifest = {
        "version": 1,
        "case_id": case_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "source": str(case_dir),
        "examiner": examiner,
        "includes_evidence": include_evidence,
        "includes_extractions": include_extractions,
        "includes_verification_ledger": ledger_included,
        "includes_password_hashes": bool(password_examiners),
        "password_examiners": password_examiners,
        "includes_opensearch": False,
        "notes": ["approvals.jsonl is an archival copy, not used for verification"],
        "files": manifest_files,
        "total_bytes": total_bytes,
        "file_count": len(manifest_files),
    }
    if purpose:
        manifest["purpose"] = purpose

    manifest_path = backup_dir / "backup-manifest.json"
    with open(manifest_path, "w") as f:
        json.dump(manifest, f, indent=2)
        f.flush()
        os.fsync(f.fileno())

    try:
        marker.unlink()
    except OSError:
        pass

    return {
        "backup_path": str(backup_dir),
        "file_count": len(manifest_files),
        "total_bytes": total_bytes,
        "total_size": human_size(total_bytes),
        "manifest": "backup-manifest.json",
        "includes_verification_ledger": ledger_included,
        "includes_opensearch": False,
        "opensearch_snapshot": {},
        "password_examiners": password_examiners,
        "ledger_note": ledger_note,
        "symlinks": scan["symlinks"],
    }
