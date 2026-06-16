"""Audit trail writer for sift-mcps MCP servers.

Each MCP writes to its own JSONL file in the case audit directory.
Canonical implementation shared by all SIFT-platform MCPs via sift-common.
"""

from __future__ import annotations

import getpass
import json
import logging
import os
import re
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

_EXAMINER_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,19}$")
_DEFAULT_STATE_DIR = "/var/lib/sift"


def _db_authority_env_active() -> bool:
    """True when the process-wide DB-authority flag is set.

    Mirrors ``sift_core.active_case_context._env_db_active`` without importing
    sift-core (sift-common must stay dependency-light). The Gateway/worker
    bootstrap sets ``SIFT_DB_ACTIVE`` when a control-plane DSN is configured;
    in that mode ``app.audit_events`` is the authoritative trail and a missing
    local JSONL ledger is expected rather than a write failure.
    """
    return os.environ.get("SIFT_DB_ACTIVE", "").strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }


def _authority_context_case_id() -> str:
    """Return the request DB case id when sift-core has bound one."""
    try:
        from sift_core.active_case_context import current_active_case
    except ImportError:
        return ""
    ctx = current_active_case()
    if ctx is None or not getattr(ctx, "db_active", False):
        return ""
    return str(getattr(ctx, "case_id", "") or "")


def _state_root_for_case(case_dir: Path) -> Path:
    configured = os.environ.get("SIFT_STATE_DIR", "").strip()
    if configured:
        return Path(configured)
    resolved = case_dir.resolve()
    if str(resolved).startswith("/tmp/"):
        return resolved.parent / ".sift-state" / resolved.name
    return Path(_DEFAULT_STATE_DIR)


def _case_id(case_dir: Path) -> str:
    meta_path = case_dir / "CASE.yaml"
    if meta_path.exists():
        try:
            import yaml

            meta = yaml.safe_load(meta_path.read_text()) or {}
            if meta.get("case_id"):
                return str(meta["case_id"])
        except Exception:
            pass
    return case_dir.name


def _case_audit_dir(case_dir: Path) -> Path:
    return _state_root_for_case(case_dir) / _case_id(case_dir) / "audit"


def _sanitize_slug(raw: str) -> str:
    """Sanitize a raw string into a valid examiner slug.

    Lowercases, replaces invalid characters with hyphens, strips leading/trailing
    hyphens, and truncates to 20 characters.
    """
    slug = re.sub(r"[^a-z0-9-]", "-", raw.lower()).strip("-")
    if len(slug) > 20:
        logger.warning(
            "Examiner slug truncated from %d to 20 chars: %s", len(slug), slug[:20]
        )
        slug = slug[:20]
    if not slug:
        return "unknown"
    slug = slug.lstrip("-")
    return slug if slug else "unknown"


def resolve_examiner() -> str:
    """Resolve examiner identity: SIFT_EXAMINER > SIFT_ANALYST > OS username.

    The result is validated against the slug pattern ^[a-z0-9][a-z0-9-]{0,19}$.
    """
    examiner = os.environ.get("SIFT_EXAMINER") or os.environ.get("SIFT_ANALYST")
    if not examiner:
        try:
            examiner = getpass.getuser()
        except Exception:
            examiner = "unknown"
    return _sanitize_slug(examiner)


class AuditWriter:
    """Writes audit entries to a per-MCP JSONL file.

    Thread-safe: sequence counter protected by lock,
    file writes wrapped in try/except with fsync for durability.
    """

    def __init__(self, mcp_name: str, audit_dir: str | None = None) -> None:
        self.mcp_name = mcp_name
        self._explicit_audit_dir = audit_dir
        self._sequence = 0
        self._date_str = ""
        self._lock = threading.Lock()

    @property
    def examiner(self) -> str:
        return resolve_examiner()

    def _get_audit_dir(self) -> Path | None:
        """Get the audit directory.

        Priority: explicit audit_dir > SIFT_AUDIT_DIR > SIFT_STATE_DIR/<case>/audit.
        """
        if self._explicit_audit_dir:
            audit_dir = Path(self._explicit_audit_dir)
        elif os.environ.get("SIFT_AUDIT_DIR"):
            audit_dir = Path(os.environ["SIFT_AUDIT_DIR"])
        else:
            case_dir = os.environ.get("SIFT_CASE_DIR", "").strip()
            # Validate: must be a directory with CASE.yaml
            if case_dir:
                path = Path(case_dir)
                if path.is_dir() and (path / "CASE.yaml").exists():
                    audit_dir = _case_audit_dir(path)
                else:
                    case_dir = ""
            if not case_dir:
                return None
        try:
            audit_dir.mkdir(parents=True, exist_ok=True)
        except OSError as e:
            logger.warning("Cannot create audit directory %s: %s", audit_dir, e)
            return None
        return audit_dir

    def _next_audit_id(self, examiner: str | None = None) -> str:
        """Generate next audit ID: {prefix}-{examiner}-{date}-{seq}.

        A single monotonic sequence is shared across all examiners (the
        examiner only varies the human-readable prefix). Per-call attribution
        is carried by ``examiner_override`` on :meth:`log`; the global counter
        keeps IDs unique without one sidecar file per principal.
        """
        if not examiner:
            examiner = self.examiner
        today = datetime.now(timezone.utc).strftime("%Y%m%d")
        with self._lock:
            if today != self._date_str:
                self._date_str = today
                self._sequence = self._resume_sequence(today)
            self._sequence += 1
            seq = self._sequence
        prefix = self.mcp_name.replace("-mcp", "").replace("-", "")
        return f"{prefix}-{examiner}-{today}-{seq:03d}"

    def _resume_sequence(self, date_str: str) -> int:
        """Resume sequence from sidecar file, falling back to JSONL scan.

        Prevents duplicate audit IDs after server restart.
        Must be called under self._lock.
        """
        audit_dir = self._get_audit_dir()
        if not audit_dir:
            return 0

        # Try sidecar first (O(1) read)
        seq_file = audit_dir / f"{self.mcp_name}.seq"
        try:
            if seq_file.exists():
                data = json.loads(seq_file.read_text())
                if data.get("date") == date_str:
                    return data.get("seq", 0)
        except (json.JSONDecodeError, OSError):
            pass

        # Fallback: scan JSONL (O(n) — only on first startup or date change).
        # The counter is global, so take the max seq across ALL examiners.
        log_file = audit_dir / f"{self.mcp_name}.jsonl"
        if not log_file.exists():
            return 0
        prefix = self.mcp_name.replace("-mcp", "").replace("-", "")
        suffix_re = re.compile(rf"-{re.escape(date_str)}-(\d+)$")
        max_seq = 0
        try:
            with open(log_file, encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line or date_str not in line:
                        continue
                    try:
                        entry = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    eid = entry.get("audit_id", "")
                    if not eid.startswith(f"{prefix}-"):
                        continue
                    m = suffix_re.search(eid)
                    if m:
                        max_seq = max(max_seq, int(m.group(1)))
        except OSError as e:
            logger.warning(
                "Failed to read audit log %s for sequence resume: %s", log_file, e
            )
        return max_seq

    def _write_seq_sidecar(self) -> None:
        """Write current sequence to sidecar for fast resume."""
        audit_dir = self._get_audit_dir()
        if not audit_dir:
            return
        seq_file = audit_dir / f"{self.mcp_name}.seq"
        try:
            with self._lock:
                date_str = self._date_str
                seq = self._sequence
            seq_file.write_text(
                json.dumps({"date": date_str, "seq": seq})
            )
        except OSError:
            pass

    def log(
        self,
        tool: str,
        params: dict[str, Any],
        result_summary: Any,
        source: str = "mcp_server",
        audit_id: str | None = None,
        case_id: str | None = None,
        elapsed_ms: float | None = None,
        input_files: list[str] | None = None,
        input_sha256s: list[str] | None = None,
        input_detection_method: str = "",
        source_evidence: str = "",
        extra: dict[str, Any] | None = None,
        examiner_override: str | None = None,
    ) -> str | None:
        """Write an audit entry. Returns the audit_id, or None when no case is active.

        DB-authority mode: when there is no local audit directory but the process
        is running under Postgres audit authority (``SIFT_DB_ACTIVE`` set by the
        Gateway/worker bootstrap), the authoritative audit trail is
        ``app.audit_events`` written by the Gateway MCP envelope, not this JSONL
        mirror. A missing local ledger is then expected, not a failure, so we
        return the (caller-supplied or freshly minted) audit_id as a clean
        no-op-success receipt rather than ``None``. File-authority mode is
        unchanged: no audit dir still returns ``None``.
        """
        if not self._get_audit_dir():
            if _db_authority_env_active():
                return audit_id or self._next_audit_id(examiner=examiner_override)
            return None
        if audit_id is None:
            audit_id = self._next_audit_id(examiner=examiner_override)

        actual_examiner = examiner_override or self.examiner
        entry = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "mcp": self.mcp_name,
            "tool": tool,
            "audit_id": audit_id,
            "examiner": actual_examiner,
            "case_id": case_id or _authority_context_case_id(),
            "source": source,
            "params": params,
            "result_summary": _summarize(result_summary),
        }
        if elapsed_ms is not None:
            entry["elapsed_ms"] = round(elapsed_ms, 1)
        if input_files:
            entry["input_files"] = input_files
            entry["input_sha256s"] = input_sha256s or []
        if input_detection_method:
            entry["input_detection_method"] = input_detection_method
        if source_evidence:
            entry["source_evidence"] = source_evidence
        if extra:
            entry.update(extra)

        if not self._write_entry(entry):
            logger.warning(
                "Audit write failed for audit_id=%s — returning None",
                audit_id,
            )
            return None
        self._write_seq_sidecar()
        return audit_id

    def _write_entry(self, entry: dict) -> bool:
        """Write a single audit entry to the JSONL file with fsync.

        Returns True if the entry was written or no case is active (normal skip).
        Returns False only on actual write errors.
        """
        audit_dir = self._get_audit_dir()
        if not audit_dir:
            logger.debug(
                "No active case, audit entry not written: %s/%s",
                self.mcp_name,
                entry.get("tool"),
            )
            return True
        try:
            log_file = audit_dir / f"{self.mcp_name}.jsonl"
            with open(log_file, "a", encoding="utf-8") as f:
                f.write(json.dumps(entry, default=str) + "\n")
                f.flush()
                os.fsync(f.fileno())
            return True
        except OSError as e:
            logger.warning(
                "Failed to write audit entry for audit_id=%s tool=%s: %s "
                "(this audit_id was NOT recorded to the audit trail)",
                entry.get("audit_id"),
                entry.get("tool"),
                e,
            )
            return False

    def get_entries(
        self, since: str | None = None, case_id: str | None = None
    ) -> list[dict]:
        """Read back audit entries, optionally filtered."""
        audit_dir = self._get_audit_dir()
        if not audit_dir:
            return []
        log_file = audit_dir / f"{self.mcp_name}.jsonl"
        if not log_file.exists():
            return []
        entries = []
        try:
            with open(log_file, encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        entry = json.loads(line)
                    except json.JSONDecodeError:
                        logger.warning("Corrupt JSONL line in %s", log_file)
                        continue
                    if since and entry.get("ts", "") < since:
                        continue
                    if case_id and entry.get("case_id", "") != case_id:
                        continue
                    entries.append(entry)
        except OSError as e:
            logger.warning("Failed to read audit entries from %s: %s", log_file, e)
        return entries

    def reset_counter(self) -> None:
        """Reset the audit ID counter. For testing only."""
        with self._lock:
            self._sequence = 0
            self._date_str = ""
        # Remove sidecar so _resume_sequence starts fresh
        audit_dir = self._get_audit_dir()
        if audit_dir:
            (audit_dir / f"{self.mcp_name}.seq").unlink(missing_ok=True)
            # Clean up any legacy per-examiner sidecars from earlier builds
            for f in audit_dir.glob(f"{self.mcp_name}-*.seq"):
                try:
                    f.unlink(missing_ok=True)
                except OSError:
                    pass


def _summarize(result: Any) -> Any:
    """Truncate large results for audit log."""
    if isinstance(result, dict):
        return result
    if isinstance(result, list):
        return {"count": len(result), "type": "list"}
    return {"value": str(result)[:500]}
