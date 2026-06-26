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

try:  # POSIX advisory file locking; absent on Windows / some minimal runtimes.
    import fcntl
except ImportError:  # pragma: no cover - platform-dependent
    fcntl = None  # type: ignore[assignment]

logger = logging.getLogger(__name__)

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

    The result is coerced to a valid slug via ``_sanitize_slug``; the canonical
    slug contract lives in ``sift_common.identifiers``.
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

    Concurrency-safe at two levels for the JSONL mirror (the Postgres
    control-plane trail in DB-authority mode is the real authority and is
    NEVER gated by either lock here):

    * In-process: ``self._lock`` (a ``threading.Lock``) serializes the
      read-modify-write of the sequence counter across threads in one process.
    * Cross-process: an advisory ``fcntl.flock(LOCK_EX)`` on a per-MCP lockfile
      in ``audit_dir`` serializes the resume-and-increment + sidecar write
      across separate processes that share one ``audit_dir`` (e.g.
      ``sift-opensearch-worker@1`` and ``@2``). Without it, two processes can
      resume the same sequence and mint DUPLICATE audit IDs.

    Lock ordering (to avoid deadlock): in the ``log()`` file-authority critical
    section the cross-process ``flock`` is OUTERMOST and held for the whole
    mint -> JSONL append -> sidecar span; the ``self._lock`` (threading.Lock) is
    taken only for the brief in-memory seq increment INSIDE that flock span. The
    two locks are always acquired in the same order (flock, then threading.Lock)
    and ``self._lock`` is never held while blocking to acquire the flock, so
    there is no lock-ordering cycle. ``_acquire_xproc_lock`` /
    ``_release_xproc_lock`` themselves do not take ``self._lock``.

    POSIX-absence degradation: when ``fcntl`` is unavailable (non-POSIX, e.g.
    Windows), the cross-process lock is a graceful no-op and behavior falls
    back to today's threading-only guarantee — it never crashes and never
    blocks. Single-process duplicate-ID safety is additionally backstopped by
    the JSONL-scan fallback in ``_resume_sequence`` (log() appends JSONL before
    the sidecar, the recoverable order).

    Durability: JSONL appends are fsync'd; the ``.seq`` sidecar is written
    atomically via temp-file + fsync + ``os.replace``.
    """

    def __init__(self, mcp_name: str, audit_dir: str | None = None) -> None:
        self.mcp_name = mcp_name
        self._explicit_audit_dir = audit_dir
        self._sequence = 0
        self._date_str = ""
        self._lock = threading.Lock()
        # Lazily-opened, reused fd for the cross-process advisory lock. flock is
        # per-open-fd, so the SAME fd must be used for LOCK_EX/LOCK_UN within a
        # critical section; we keep one fd for the writer's lifetime.
        self._lock_fd: int | None = None

    @property
    def examiner(self) -> str:
        return resolve_examiner()

    def _get_lock_fd(self) -> int | None:
        """Return a (lazily-opened) fd for the cross-process advisory lock.

        Opens ``audit_dir / "{mcp_name}.lock"`` once and reuses the fd for the
        writer's lifetime (flock is per-open-fd). Returns ``None`` when fcntl is
        unavailable (non-POSIX) or when there is no audit dir / the lockfile
        cannot be opened — callers then degrade to threading-only behavior.
        """
        if fcntl is None:
            return None
        # Fast path: fd already open (no lock needed for a plain pointer read).
        if self._lock_fd is not None:
            return self._lock_fd
        audit_dir = self._get_audit_dir()
        if not audit_dir:
            return None
        lock_path = audit_dir / f"{self.mcp_name}.lock"
        # Atomic check-and-open under self._lock: without it two threads that
        # both observe ``self._lock_fd is None`` would each os.open the lockfile,
        # leaking an fd AND — since flock is per-open-file-description — handing
        # the two callers DIFFERENT fds from the same process that block each
        # other. Reusing self._lock is deadlock-free: the sole caller chain
        # (_get_lock_fd <- _acquire_xproc_lock <- log()) acquires the flock
        # BEFORE taking self._lock for the in-memory mint, so self._lock is never
        # held when this runs. Holding the same lock here also keeps every
        # mutation of self._lock_fd (here and in close()) serialized under one
        # lock.
        with self._lock:
            # Re-check inside the lock: another thread may have opened it while
            # we waited.
            if self._lock_fd is not None:
                return self._lock_fd
            try:
                # O_CREAT so the lockfile exists; the fd content is never read.
                self._lock_fd = os.open(
                    str(lock_path), os.O_RDWR | os.O_CREAT, 0o644
                )
            except OSError as e:
                logger.warning("Cannot open audit lockfile %s: %s", lock_path, e)
                self._lock_fd = None
            return self._lock_fd

    def _acquire_xproc_lock(self) -> int | None:
        """Acquire the exclusive cross-process advisory lock; return the fd.

        Acquired OUTERMOST (before ``self._lock``) in the ``log()`` critical
        section. Does NOT itself take ``self._lock``. Returns the locked fd on
        success, or ``None`` when locking is unavailable (graceful no-op
        fallback to threading-only serialization). Never raises on lock failure
        — degrades. Block-acquire (LOCK_EX) is bounded by sibling holders only.
        """
        fd = self._get_lock_fd()
        if fd is None:
            return None
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)  # type: ignore[union-attr]
            return fd
        except OSError as e:
            logger.warning("flock(LOCK_EX) failed on audit lockfile: %s", e)
            return None

    def _release_xproc_lock(self, fd: int | None) -> None:
        """Release the cross-process advisory lock acquired via ``_acquire_xproc_lock``.

        Released LAST (after every ``self._lock`` acquire/release in the span
        has completed). A no-op when ``fd`` is ``None`` (locking was
        unavailable).
        """
        if fd is None or fcntl is None:
            return
        try:
            fcntl.flock(fd, fcntl.LOCK_UN)  # type: ignore[union-attr]
        except OSError as e:
            logger.warning("flock(LOCK_UN) failed on audit lockfile: %s", e)

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
            seq = self._mint_seq_locked(today)
        prefix = self.mcp_name.replace("-mcp", "").replace("-", "")
        return f"{prefix}-{examiner}-{today}-{seq:03d}"

    def _mint_seq_locked(self, today: str) -> int:
        """Resume + increment the sequence. Caller MUST hold ``self._lock``.

        Re-resumes from disk every call so a value another process committed
        (under the cross-process flock) is observed, then advances. This is the
        in-memory increment only; persistence (sidecar) is done by the caller
        while still holding the cross-process lock so the JSONL-then-sidecar
        recoverable order is preserved.
        """
        resumed = self._resume_sequence(today)
        if today != self._date_str:
            self._date_str = today
            self._sequence = resumed
        else:
            # Another process may have advanced the on-disk seq past us.
            self._sequence = max(self._sequence, resumed)
        self._sequence += 1
        return self._sequence

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
        except (json.JSONDecodeError, OSError, UnicodeDecodeError, ValueError):
            # Corrupted or unreadable sidecar — fall through to JSONL scan.
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

    def _write_seq_sidecar_locked(self, date_str: str, seq: int) -> None:
        """Atomically persist the sequence sidecar (temp + fsync + os.replace).

        Crash-safe: a torn/partial sidecar is impossible because the file is
        first fully written to a per-pid temp path in the SAME directory,
        fsync'd, then atomically renamed over the target via ``os.replace``
        (atomic on POSIX). On any OSError the temp file is cleaned up and the
        call is a graceful no-op (matching the prior best-effort contract).

        Caller MUST already hold ``self._lock`` (and, in ``_next_audit_id``, the
        cross-process flock) so the passed ``date_str``/``seq`` are consistent.
        """
        audit_dir = self._get_audit_dir()
        if not audit_dir:
            return
        seq_file = audit_dir / f"{self.mcp_name}.seq"
        tmp_file = seq_file.with_name(
            seq_file.name + f".tmp.{os.getpid()}.{threading.get_ident()}"
        )
        payload = json.dumps({"date": date_str, "seq": seq})
        try:
            with open(tmp_file, "w", encoding="utf-8") as f:
                f.write(payload)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp_file, seq_file)
        except OSError:
            try:
                tmp_file.unlink(missing_ok=True)
            except OSError:
                pass

    def _write_seq_sidecar(self) -> None:
        """Write the current sequence to the sidecar (atomic, fast-resume hint).

        Snapshots the counter under ``self._lock`` then delegates to the atomic
        writer. Retained for backward compatibility; in the normal log() path
        the sidecar is already persisted inside ``_next_audit_id`` under the
        cross-process lock, so this is a (cheap, idempotent) re-affirmation.
        """
        with self._lock:
            date_str = self._date_str
            seq = self._sequence
        self._write_seq_sidecar_locked(date_str, seq)

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
            # DB-authority path: NEVER gated by the cross-process file lock —
            # the authoritative trail is Postgres, not this JSONL mirror.
            if _db_authority_env_active():
                return audit_id or self._next_audit_id(examiner=examiner_override)
            return None

        actual_examiner = examiner_override or self.examiner

        def _build_entry(aid: str) -> dict[str, Any]:
            entry: dict[str, Any] = {
                "ts": datetime.now(timezone.utc).isoformat(),
                "mcp": self.mcp_name,
                "tool": tool,
                "audit_id": aid,
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
            return entry

        # File-authority critical section. Lock ordering (deadlock-free):
        # cross-process flock OUTERMOST, then per-step threading.Lock for the
        # in-memory mint. The flock spans mint -> JSONL append -> sidecar so the
        # JSONL-then-sidecar recoverable order is atomic across processes that
        # share one audit_dir (else two processes resume the same seq and mint
        # duplicate IDs). flock is released after the sidecar write. When fcntl
        # is unavailable the flock is a graceful no-op (threading-only).
        today = datetime.now(timezone.utc).strftime("%Y%m%d")
        xfd = self._acquire_xproc_lock()
        try:
            minted_here = audit_id is None
            if minted_here:
                with self._lock:
                    seq = self._mint_seq_locked(today)
                    date_str = self._date_str
                prefix = self.mcp_name.replace("-mcp", "").replace("-", "")
                minted_id = f"{prefix}-{actual_examiner}-{today}-{seq:03d}"
            else:
                minted_id = audit_id

            entry = _build_entry(minted_id)

            # JSONL append FIRST (the durable, recoverable record), then sidecar
            # — the order _resume_sequence relies on after a crash.
            if not self._write_entry(entry):
                logger.warning(
                    "Audit write failed for audit_id=%s — returning None",
                    minted_id,
                )
                return None
            # Persist the sidecar only when WE minted the seq; a caller-supplied
            # audit_id must not roll the on-disk counter back to a stale value.
            if minted_here:
                self._write_seq_sidecar_locked(date_str, seq)
        finally:
            self._release_xproc_lock(xfd)
        return minted_id

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

    def close(self) -> None:
        """Release the cross-process lock fd. Idempotent; safe to call once done."""
        with self._lock:
            fd = self._lock_fd
            self._lock_fd = None
        if fd is not None:
            try:
                os.close(fd)
            except OSError:
                pass

    def __del__(self) -> None:  # pragma: no cover - best-effort fd cleanup
        try:
            self.close()
        except Exception:
            pass


def _summarize(result: Any) -> Any:
    """Truncate large results for audit log."""
    if isinstance(result, dict):
        return result
    if isinstance(result, list):
        return {"count": len(result), "type": "list"}
    return {"value": str(result)[:500]}
