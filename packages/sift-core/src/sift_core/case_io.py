"""Shared case file I/O.

Local-first: flat case directory. Collaboration via export/merge.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

import yaml

_EXAMINER_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,19}$")

DEFAULT_CASES_DIR = str(Path.home() / "cases")
_CASE_SUBDIRS = frozenset({"evidence", "extractions", "reports", "audit", "tmp", "agent"})


class CaseError(Exception):
    """Raised when case directory cannot be resolved or validation fails."""


def cases_root() -> Path:
    """Resolve the cases-root directory — the parent that holds all case dirs.

    Single source of truth for cases-root resolution across the gateway,
    portal, ingest CLI, and every backend. Precedence:

      ``SIFT_CASES_ROOT``  — set by the gateway from ``gateway.yaml`` ``case.root``
      → ``SIFT_CASES_DIR`` — legacy alias
      → ``~/cases``        — :data:`DEFAULT_CASES_DIR`

    Every cases-root lookup must route through here so the env precedence is
    defined exactly once (no scattered, drifting ``os.environ.get`` calls).
    For the *active* case directory (singular) use :func:`get_case_dir`.
    """
    return Path(
        os.environ.get("SIFT_CASES_ROOT")
        or os.environ.get("SIFT_CASES_DIR")
        or DEFAULT_CASES_DIR
    )


def _validate_case_id(case_id: str) -> None:
    if not case_id:
        raise CaseError("Case ID cannot be empty")
    if ".." in case_id or "/" in case_id or "\\" in case_id:
        raise CaseError(f"Invalid case ID (path traversal characters): {case_id}")


def _validate_examiner(examiner: str) -> None:
    if not examiner or not _EXAMINER_RE.match(examiner):
        raise CaseError(f"Invalid examiner slug: {examiner!r}")


def _atomic_write(path: Path, content: str) -> None:
    """Write file atomically via temp file + rename to prevent data loss on crash."""
    fd, tmp_path = tempfile.mkstemp(dir=path.parent, suffix=".tmp")
    try:
        with os.fdopen(fd, "w") as f:
            f.write(content)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp_path, path)
    except BaseException:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise


def _protected_write(path: Path, content: str) -> None:
    """Write to a chmod-444-protected case data file.

    Unlocks (0o644) before write, locks (0o444) after.
    """
    try:
        if path.exists():
            os.chmod(path, 0o644)
    except OSError:
        pass
    _atomic_write(path, content)
    try:
        os.chmod(path, 0o444)
    except OSError:
        pass


def get_case_dir(case_id: str | None = None) -> Path:
    """Resolve the active case directory."""
    if case_id:
        _validate_case_id(case_id)
        case_dir = cases_root() / case_id
        if not case_dir.exists():
            raise CaseError(f"Case not found: {case_id}")
        return case_dir

    env_dir = os.environ.get("SIFT_CASE_DIR")
    if env_dir:
        case_dir = Path(env_dir)
        if not case_dir.is_dir():
            raise CaseError(f"Case directory does not exist: {case_dir}")
        return case_dir

    raise CaseError(
        "No active case: set SIFT_CASE_DIR in ~/.sift/gateway.yaml case.dir"
    )


def resolve_case_path(
    path: str,
    *,
    case_dir: Path | None = None,
    default_subdir: str = "evidence",
) -> Path:
    """Resolve a tool path argument against the active case directory.

    Absolute paths are allowed only when they resolve inside the case. Relative
    paths beginning with a known case subdirectory are resolved from the case
    root. Bare filenames default to ``case_dir/default_subdir``.
    """
    if case_dir is None:
        env = os.environ.get("SIFT_CASE_DIR", "").strip()
        if not env:
            raise ValueError("No active case. Use the Examiner Portal to create a case first.")
        case_dir = Path(env)

    case_root = case_dir.resolve()
    raw_path = "" if path is None else str(path).strip()
    if not raw_path:
        raise ValueError("Path cannot be empty.")

    p = Path(raw_path)
    if p.is_absolute():
        resolved = p.resolve()
    elif p.parts and p.parts[0] in _CASE_SUBDIRS:
        resolved = (case_root / p).resolve()
    else:
        resolved = (case_root / default_subdir / p).resolve()

    if not resolved.is_relative_to(case_root):
        raise ValueError(
            f"Path {raw_path!r} resolves outside case directory. "
            "Use a relative path like 'evidence/filename.e01'."
        )
    return resolved


def get_examiner(case_dir: Path | None = None) -> str:
    """Get the current examiner identity.

    Resolution: SIFT_EXAMINER > SIFT_ANALYST (deprecated) > CASE.yaml > OS user.
    """
    env_exam = os.environ.get("SIFT_EXAMINER", "").strip().lower()
    if env_exam:
        _validate_examiner(env_exam)
        return env_exam
    env_analyst = os.environ.get("SIFT_ANALYST", "").strip().lower()
    if env_analyst:
        _validate_examiner(env_analyst)
        return env_analyst
    if case_dir:
        meta = load_case_meta(case_dir)
        exam = meta.get("examiner", "").strip().lower()
        if exam:
            _validate_examiner(exam)
            return exam
    import getpass

    fallback = getpass.getuser().strip().lower()
    _validate_examiner(fallback)
    return fallback


def load_case_meta(case_dir: Path) -> dict:
    meta_file = case_dir / "CASE.yaml"
    if not meta_file.exists():
        return {}
    try:
        with open(meta_file) as f:
            return yaml.safe_load(f) or {}
    except (yaml.YAMLError, OSError):
        return {}


def check_case_file_integrity(case_dir: Path, filename: str) -> None:
    path = case_dir / filename
    if not path.exists():
        return
    try:
        raw = path.read_text().strip()
    except OSError as e:
        raise RuntimeError(f"Cannot read {filename}: {e}") from e
    if not raw or raw == "[]":
        return
    try:
        json.loads(raw)
    except json.JSONDecodeError as e:
        raise RuntimeError(
            f"{filename} is corrupt and cannot be parsed: {e}. "
            "Verify file integrity before proceeding."
        ) from e


def load_findings(case_dir: Path) -> list[dict]:
    findings_file = case_dir / "findings.json"
    if not findings_file.exists():
        return []
    try:
        return json.loads(findings_file.read_text())
    except json.JSONDecodeError as e:
        print(f"WARNING: Corrupt findings.json ({findings_file}): {e}", file=sys.stderr)
        return []


def save_findings(case_dir: Path, findings: list[dict]) -> None:
    _protected_write(
        case_dir / "findings.json",
        json.dumps(findings, indent=2, default=str),
    )


def load_timeline(case_dir: Path) -> list[dict]:
    timeline_file = case_dir / "timeline.json"
    if not timeline_file.exists():
        return []
    try:
        return json.loads(timeline_file.read_text())
    except json.JSONDecodeError as e:
        print(f"WARNING: Corrupt timeline.json ({timeline_file}): {e}", file=sys.stderr)
        return []


def save_timeline(case_dir: Path, timeline: list[dict]) -> None:
    _protected_write(
        case_dir / "timeline.json",
        json.dumps(timeline, indent=2, default=str),
    )


def load_todos(case_dir: Path) -> list[dict]:
    todos_file = case_dir / "todos.json"
    if not todos_file.exists():
        return []
    try:
        return json.loads(todos_file.read_text())
    except json.JSONDecodeError as e:
        print(f"WARNING: Corrupt todos.json ({todos_file}): {e}", file=sys.stderr)
        return []


def save_todos(case_dir: Path, todos: list[dict]) -> None:
    _atomic_write(
        case_dir / "todos.json",
        json.dumps(todos, indent=2, default=str),
    )


def load_iocs(case_dir: Path) -> list[dict]:
    iocs_file = case_dir / "iocs.json"
    if not iocs_file.exists():
        return []
    try:
        return json.loads(iocs_file.read_text())
    except json.JSONDecodeError as e:
        print(f"WARNING: Corrupt iocs.json ({iocs_file}): {e}", file=sys.stderr)
        return []


def save_iocs(case_dir: Path, iocs: list[dict]) -> None:
    _protected_write(
        case_dir / "iocs.json",
        json.dumps(iocs, indent=2, default=str),
    )


def load_evidence(case_dir: Path) -> list[dict]:
    evidence_file = case_dir / "evidence.json"
    if not evidence_file.exists():
        return []
    try:
        return json.loads(evidence_file.read_text())
    except json.JSONDecodeError as e:
        print(f"WARNING: Corrupt evidence.json ({evidence_file}): {e}", file=sys.stderr)
        return []


def write_approval_log(
    case_dir: Path,
    item_id: str,
    action: str,
    identity: dict,
    reason: str = "",
    mode: str = "interactive",
    content_hash: str = "",
    stale_at_approval: bool = False,
    coupled_from: str = "",
) -> bool:
    log_file = case_dir / "approvals.jsonl"
    entry = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "item_id": item_id,
        "action": action,
        "os_user": identity["os_user"],
        "examiner": identity.get("examiner", identity.get("analyst", "")),
        "examiner_source": identity.get(
            "examiner_source", identity.get("analyst_source", "")
        ),
        "mode": mode,
    }
    if reason:
        entry["reason"] = reason
    if content_hash:
        entry["content_hash"] = content_hash
    if stale_at_approval:
        entry["stale_at_approval"] = True
    if coupled_from:
        entry["coupled_from"] = coupled_from
    try:
        if log_file.exists():
            os.chmod(log_file, 0o644)
    except OSError:
        pass
    try:
        with open(log_file, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry) + "\n")
            f.flush()
            os.fsync(f.fileno())
    except OSError:
        print(f"WARNING: Failed to write approval log: {log_file}", file=sys.stderr)
        return False
    try:
        os.chmod(log_file, 0o444)
    except OSError:
        pass
    return True


def load_approval_log(case_dir: Path) -> list[dict]:
    log_file = case_dir / "approvals.jsonl"
    if not log_file.exists():
        return []
    entries = []
    corrupt_lines = 0
    with open(log_file, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                entries.append(json.loads(line))
            except json.JSONDecodeError:
                corrupt_lines += 1
                continue
    if corrupt_lines:
        print(
            f"Warning: {corrupt_lines} corrupt line(s) skipped in approvals.jsonl",
            file=sys.stderr,
        )
    return entries


def find_draft_item(
    item_id: str, findings: list[dict], timeline: list[dict]
) -> dict | None:
    for f in findings:
        if f["id"] == item_id and f["status"] == "DRAFT":
            return f
    for t in timeline:
        if t["id"] == item_id and t["status"] == "DRAFT":
            return t
    return None


HASH_EXCLUDE_KEYS = {
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


def compute_content_hash(item: dict) -> str:
    """SHA-256 of canonical JSON excluding volatile fields."""
    hashable = {k: v for k, v in item.items() if k not in HASH_EXCLUDE_KEYS}
    canonical = json.dumps(hashable, sort_keys=True, default=str)
    return hashlib.sha256(canonical.encode()).hexdigest()


def hmac_text(item: dict) -> str:
    hashable = {k: v for k, v in item.items() if k not in HASH_EXCLUDE_KEYS}
    return json.dumps(hashable, sort_keys=True, default=str)


def verify_approval_integrity(case_dir: Path) -> list[dict]:
    findings = load_findings(case_dir)
    approvals = load_approval_log(case_dir)
    last_approval = {}
    for record in approvals:
        last_approval[record["item_id"]] = record
    results = []
    for f in findings:
        result = dict(f)
        status = f.get("status", "DRAFT")
        fid = f["id"]
        record = last_approval.get(fid)
        if status == "DRAFT":
            result["verification"] = "draft"
        elif record:
            if record["action"] == status:
                recomputed = compute_content_hash(f)
                finding_hash = f.get("content_hash")
                approval_hash = record.get("content_hash")
                if finding_hash and recomputed != finding_hash:  # noqa: SIM114
                    result["verification"] = "tampered"
                elif approval_hash and recomputed != approval_hash:
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


def load_audit_index(case_dir: Path) -> dict[str, dict]:
    """Scan audit/*.jsonl and build {audit_id: entry} index."""
    audit_dir = case_dir / "audit"
    index: dict[str, dict] = {}
    if not audit_dir.is_dir():
        return index
    for jsonl_file in sorted(audit_dir.glob("*.jsonl")):
        try:
            with open(jsonl_file, encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        entry = json.loads(line)
                        eid = entry.get("audit_id", "")
                        if eid:
                            entry["_source_file"] = jsonl_file.name
                            index[eid] = entry
                    except json.JSONDecodeError:
                        continue
        except OSError:
            continue
    return index


def export_bundle(case_dir: Path, since: str = "") -> dict:
    """Export findings + timeline as JSON for sharing."""
    meta = load_case_meta(case_dir)
    findings = load_findings(case_dir)
    timeline = load_timeline(case_dir)
    if since:
        findings = [
            f for f in findings if f.get("modified_at", f.get("staged", "")) >= since
        ]
        timeline = [
            t for t in timeline if t.get("modified_at", t.get("staged", "")) >= since
        ]
    return {
        "case_id": meta.get("case_id", ""),
        "examiner": get_examiner(case_dir),
        "exported_at": datetime.now(timezone.utc).isoformat(),
        "findings": findings,
        "timeline": timeline,
    }


def import_bundle(case_dir: Path, bundle: dict | list) -> dict:
    """Merge incoming bundle into local findings + timeline."""
    if isinstance(bundle, list):
        bundle = {"findings": bundle}
    if not isinstance(bundle, dict):
        return {"status": "error", "message": "Bundle must be a JSON object or array"}

    findings_result: dict = {"added": 0, "updated": 0, "skipped": 0}
    timeline_result: dict = {"added": 0, "updated": 0, "skipped": 0}

    if "findings" in bundle:
        findings_result = _merge_items(case_dir, "findings.json", bundle["findings"], "id")
    if "timeline" in bundle:
        timeline_result = _merge_items(case_dir, "timeline.json", bundle["timeline"], "id")

    return {"status": "merged", "findings": findings_result, "timeline": timeline_result}


def _parse_ts(ts: str) -> datetime:
    if ts.endswith("Z"):
        ts = ts[:-1] + "+00:00"
    try:
        return datetime.fromisoformat(ts)
    except (ValueError, TypeError):
        return datetime.min.replace(tzinfo=timezone.utc)


def _merge_items(
    case_dir: Path, filename: str, incoming: list[dict], id_field: str
) -> dict:
    local_file = case_dir / filename
    local: list[dict] = []
    if local_file.exists():
        try:
            local = json.loads(local_file.read_text())
        except json.JSONDecodeError:
            pass

    local_by_id = {item[id_field]: item for item in local if id_field in item}
    added = updated = skipped = protected = 0

    _MERGE_PROTECTED_FIELDS = {
        "id", "status", "staged", "modified_at", "created_by", "examiner", "provenance",
    }

    for item in incoming:
        item_id = item.get(id_field, "")
        if not item_id:
            skipped += 1
            continue
        cleaned = {k: v for k, v in item.items() if k not in _MERGE_PROTECTED_FIELDS}
        cleaned["status"] = "DRAFT"
        cleaned[id_field] = item_id
        if item_id not in local_by_id:
            local.append(cleaned)
            local_by_id[item_id] = cleaned
            added += 1
        else:
            existing = local_by_id[item_id]
            if existing.get("status") == "APPROVED":
                protected += 1
                continue
            inc_ts = item.get("modified_at", item.get("staged", ""))
            loc_ts = existing.get("modified_at", existing.get("staged", ""))
            if _parse_ts(inc_ts) > _parse_ts(loc_ts):
                idx = next(i for i, x in enumerate(local) if x.get(id_field) == item_id)
                local[idx] = cleaned
                local_by_id[item_id] = cleaned
                updated += 1
            else:
                skipped += 1

    _protected_write(local_file, json.dumps(local, indent=2, default=str))
    return {"added": added, "updated": updated, "skipped": skipped, "protected": protected}
