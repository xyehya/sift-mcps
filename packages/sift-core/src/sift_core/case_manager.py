"""Case manager: investigation records, TODOs, evidence listing, grounding.

Local-first: each examiner owns a flat case directory. Case lifecycle
(init, close, activate) is handled by the core case tools and the SIFT CLI.
"""

from __future__ import annotations

import json
import logging
import os
import re
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml
from sift_common.audit import resolve_examiner
from sift_common.identifiers import is_valid_examiner_slug

from sift_core.case_io import case_audit_dir, cases_root, state_root
from sift_core.case_ops import build_case_brief
from sift_core.evidence_chain import load_manifest
from sift_core.evidence_ops import list_manifest_evidence_data
from sift_core.finding_validation import validate as validate_finding_data
from sift_core.investigation_store import compute_content_hash as _compute_content_hash

logger = logging.getLogger(__name__)
ReferenceBackendProvider = Any
_reference_backend_provider: ReferenceBackendProvider | None = None

# C1 (operator decision): the human examiner must see FULL, unredacted
# command/purpose in the portal — this is a single-tenant FORENSIC appliance.
# Redaction applies ONLY to what AGENTS receive (response_guard / redact_structured
# in the gateway). This constant is a DB-bloat guard ONLY, not secret protection.
_SHELL_AUDIT_FIELD_MAX = 8000


def _bound_supporting_command(value: Any) -> str:
    """Bound an agent-narrated supporting-command string for audit storage.

    Hard-bounds length to ``_SHELL_AUDIT_FIELD_MAX`` (DB-bloat guard only —
    NOT a secret scrubber; see C1). The command is also stored in the local
    JSONL ledger by ``audit.log`` (file mode); this bound governs only the
    DB-mode app.audit_events row written by B-D3.

    Never raises — on any error returns a short marker rather than the original.
    """
    try:
        s = str(value or "")
        if len(s) > _SHELL_AUDIT_FIELD_MAX:
            s = s[:_SHELL_AUDIT_FIELD_MAX] + "...[truncated]"
        return s
    except Exception:  # noqa: BLE001 — defensive: never propagate
        return "[error: could not convert to string]"


def _persist_shell_audit_event(
    shell_eid: str,
    *,
    command: str,
    purpose: str,
    case_id: str,
    examiner: str = "",
) -> None:
    """Forward-write ONE ``app.audit_events`` row for a supporting command (B-D3).

    ``shell-*`` ids are minted inside ``record_finding`` for agent-narrated
    supporting commands and written only to the local JSONL ledger, so they
    don't resolve in the DB-mode portal provenance panel. This persists a
    citable row keyed by ``shell_eid`` as ``details.backend_audit_id`` (the
    column the §9.6 case-scoped resolver matches), case-scoped to the case UUID.

    Caller contract: only invoke when DB-active (``case_id`` is the case UUID,
    never None). Fail-soft: any DSN/psycopg/insert error is raised to the caller
    only via return-by-exception — the caller wraps this and appends to
    ``audit_warnings``; it must NEVER block record_finding. The command/purpose
    are length-bounded before storage (C1: full values stored — operator sees
    unredacted forensic detail in the portal; agent-facing redaction is in the
    gateway response_guard, not here).

    C4: reuses one cached write connection per (pid, dsn) via the E1-methodology
    audit-write connection cache in investigation_store. Any error evicts the
    cached connection so the next call gets a fresh socket.
    """
    # L-1b: prefer the least-privilege audit-writer DSN when configured; fall
    # back to the full control-plane DSN otherwise (non-breaking rollout).
    from sift_core.investigation_store import (
        audit_forward_write_dsn,
        borrow_audit_write_connection,
        evict_audit_write_connection,
    )

    dsn = audit_forward_write_dsn()
    if not dsn or not case_id or not shell_eid:
        return
    from psycopg.types.json import Jsonb

    details = {
        "backend_audit_id": str(shell_eid),
        "command": _bound_supporting_command(command),
        "purpose": _bound_supporting_command(purpose),
    }
    sql = (
        "insert into app.audit_events "
        "(event_type, actor_type, source, status, case_id, summary, details) "
        "values (%s, %s, %s, %s, %s, %s, %s)"
    )
    values = [
        "finding.supporting_command",
        "service",
        "shell_self_report",
        "success",
        str(case_id),
        "supporting command",
        Jsonb(details),
    ]
    conn = borrow_audit_write_connection(dsn)
    try:
        with conn.cursor() as cur:
            cur.execute(sql, values)
        conn.commit()
    except Exception:
        # Evict the (possibly dead/poisoned) connection; the next call gets fresh.
        evict_audit_write_connection(dsn)
        raise


def set_reference_backend_provider(provider: ReferenceBackendProvider | None) -> None:
    """Install the gateway/backend-manifest lookup used by grounding."""
    global _reference_backend_provider
    _reference_backend_provider = provider


def _declared_reference_backends() -> list[str]:
    if _reference_backend_provider is not None:
        try:
            return list(_reference_backend_provider() or [])
        except TypeError:
            return list(_reference_backend_provider("reference") or [])
    configured = os.environ.get("SIFT_REFERENCE_BACKENDS", "").strip()
    if not configured:
        return []
    return [name.strip() for name in configured.split(",") if name.strip()]


# Declaration-driven capability summary. The gateway injects a provider that
# returns the REGISTERED + AVAILABLE backends and the capabilities their
# manifests advertise. We never probe installed packages or hardcode add-on
# names: a capability is "available" only when a registered backend advertises
# it (mirrors the reference-backend / grounding model).
_backend_capability_provider: Any | None = None


def set_backend_capability_provider(provider: Any | None) -> None:
    """Install the gateway lookup for available backends + advertised provides."""
    global _backend_capability_provider
    _backend_capability_provider = provider


def _available_backend_capabilities() -> list[dict]:
    """[{name, namespace, provides:[...]}] for registered+available backends.

    Empty when no gateway/provider is wired (e.g. sift_core used standalone) —
    correct: no gateway means no registered backends means no add-on
    capabilities to advertise.
    """
    if _backend_capability_provider is not None:
        try:
            return list(_backend_capability_provider() or [])
        except Exception:
            logger.debug("backend capability provider failed", exc_info=True)
            return []
    return []


def _db_audit_event_has_audit_id(
    dsn: str, case_id: str | None, candidates: list[str]
) -> bool:
    """True when ``app.audit_events`` records one of the candidate audit ids.

    The gateway envelope middleware stores each tool call's backend audit id in
    ``details->>'backend_audit_id'`` (and some writers use ``details->>'audit_id'``).
    Gateway canonical UUIDs are stored in ``details->>'envelope_event_id'`` on the
    result row and also matched here so agents citing an envelope_event_id can resolve.
    Scoped to the case when the case UUID is known. Lightweight single-row probe.
    """
    if not candidates:
        return False
    import psycopg

    match = (
        "(details->>'backend_audit_id' = any(%s)"
        " or details->>'audit_id' = any(%s)"
        " or details->>'envelope_event_id' = any(%s))"
    )
    with psycopg.connect(dsn) as conn:
        with conn.cursor() as cur:
            if case_id:
                cur.execute(
                    f"select 1 from app.audit_events where case_id = %s and {match} limit 1",
                    (case_id, candidates, candidates, candidates),
                )
            else:
                cur.execute(
                    f"select 1 from app.audit_events where {match} limit 1",
                    (candidates, candidates, candidates),
                )
            return cur.fetchone() is not None


def build_platform_capabilities() -> dict:
    """Capability summary derived ONLY from registered, available backends and
    the capabilities their manifests advertise. No installed-package probing,
    no hardcoded add-on/tool names (R-no-hardcoded-names)."""
    backends = _available_backend_capabilities()
    provides_union = sorted({p for b in backends for p in (b.get("provides") or [])})
    caps = {
        "sift_tools": True,  # core forensic tools via run_command are always present
        "provides": provides_union,
        "backends": [
            {
                "name": b.get("name", ""),
                "namespace": b.get("namespace", ""),
                "provides": list(b.get("provides") or []),
            }
            for b in backends
        ],
    }
    guidance = [
        "Available investigation capabilities:",
        "- SIFT forensic tools via run_command",
    ]
    for b in backends:
        label = b.get("namespace") or b.get("name") or "add-on"
        prov = ", ".join(b.get("provides") or []) or "tools"
        guidance.append(f"- {label} add-on available (provides: {prov})")
    guidance.append("")
    guidance.append(
        "For core forensic tool usage use get_tool_help(tool_name='...'). "
        "capability_guide lists ADD-ON backend tools only. Use tools/list for "
        "exact input schemas before calling a tool."
    )
    return {
        "platform_capabilities": caps,
        "investigation_guidance": "\n".join(guidance),
    }


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

    Uses atomic write (tempfile + rename), then locks (0o444).
    The temp file is created writable, so we only need to unlock the
    existing file for _atomic_write's rename to succeed on the same inode.
    """
    try:
        if path.exists():
            os.chmod(path, 0o644)
    except OSError:
        pass  # May already be writable or on non-POSIX fs
    try:
        _atomic_write(path, content)
    finally:
        # Always re-lock, even if the write failed partway
        try:
            if path.exists():
                os.chmod(path, 0o444)
        except OSError:
            pass  # Non-POSIX filesystem


_ACTIVE_CASE_FILE = Path.home() / ".sift" / "active_case"

# Audit ID format: prefix-examiner-YYYYMMDD-NNN (all lowercase alphanumeric + hyphens).
# The prefix segment is ``[a-z][a-z0-9]*`` (must START with a letter — the
# anti-injection guarantee — but may then carry digits). The opensearch ingest
# scheme embeds the worker PID in the prefix, e.g.
# ``opensearchingest1018805-sift-service-20260623-040``; a letters-only ``[a-z]+``
# prefix wrongly rejected those, so a finding citing a real ingest id was denied
# "no evidence trail" before the DB authority check ran (Gap B live-prove fix).
_AUDIT_ID_PATTERN = re.compile(
    r"^[a-z][a-z0-9]*-[a-z0-9](?:[a-z0-9-]*[a-z0-9])?-[0-9]{8}-[0-9]{3,}\Z"
)

# Gateway canonical UUID: 8-4-4-4-12 hex (envelope_event_id assigned by AuditEnvelopeMiddleware).
# These are accepted as valid provenance citations and routed to the DB authority check.
_UUID_PATTERN = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\Z",
    re.IGNORECASE,
)

# Allowlist: only these fields pass through from user-supplied finding data
_ALLOWED_FINDING_FIELDS = {
    "title",
    "observation",
    "interpretation",
    "confidence",
    "confidence_justification",
    "type",
    "audit_ids",
    "mitre_ids",
    "iocs",
    "event_type",
    "artifact_ref",
    "related_findings",
    "supersedes",
    "host",
    "event_timestamp",
    "affected_account",
}
_PROTECTED_EVENT_FIELDS = {
    "id",
    "status",
    "staged",
    "modified_at",
    "created_by",
    "examiner",
}

# BATCH-NW1: _HASH_EXCLUDE_KEYS and _compute_content_hash have been removed.
# The single shared implementation is investigation_store.compute_content_hash,
# imported above as _compute_content_hash to preserve existing call sites within
# this module without further changes.  See investigation_store.HASH_EXCLUDE_KEYS
# for the authoritative 19-key exclude set and the re-hash migration note.


def _next_seq(items: list[dict], id_field: str, prefix: str, examiner: str) -> int:
    """Find max sequence number for IDs matching {prefix}-{examiner}-NNN."""
    pattern = f"{prefix}-{examiner}-"
    max_num = 0
    for item in items:
        item_id = item.get(id_field, "")
        if item_id.startswith(pattern):
            try:
                num = int(item_id[len(pattern) :])
                max_num = max(max_num, num)
            except ValueError:
                pass
    return max_num + 1


def _resolve_source_evidence_static(
    input_files: list[str],
    audit_entries: list[dict],
    evidence_registry: set[str],
    visited: set[str] | None = None,
    depth: int = 0,
    max_depth: int = 10,
    evidence_by_hash: dict[str, str] | None = None,
    output_to_inputs: dict[str, list[str]] | None = None,
    output_to_entry: dict[str, dict] | None = None,
    hostname_hint: str = "",
) -> tuple[str, list[dict]]:
    """Walk input files backward through audit trail to find registered evidence.

    Returns (evidence_path, chain_steps) where chain_steps records each
    intermediate audit entry traversed during the walk.
    """
    if depth >= max_depth:
        return "", []
    if visited is None:
        visited = set()
    # Build output→input_files and output→entry lookups once at depth 0
    if output_to_inputs is None:
        output_to_inputs = {}
        output_to_entry = {}
        for entry in audit_entries:
            inp = entry.get("input_files", [])
            rs = entry.get("result_summary", {})
            if isinstance(rs, dict):
                of = rs.get("output_file", "")
                if of:
                    try:
                        key = str(Path(of).resolve())
                        output_to_inputs[key] = inp
                        output_to_entry[key] = entry
                    except OSError:
                        pass
                for of in rs.get("output_files", []):
                    if of:
                        try:
                            key = str(Path(of).resolve())
                            output_to_inputs[key] = inp
                            output_to_entry[key] = entry
                        except OSError:
                            pass
    if output_to_entry is None:
        output_to_entry = {}
    for path in input_files:
        resolved = str(Path(path).resolve())
        if resolved in visited:
            continue
        visited.add(resolved)
        if resolved in evidence_registry:
            return resolved, []
        # Directory containment
        resolved_prefix = resolved.rstrip("/") + "/"
        containment_match = ""
        for reg_path in sorted(evidence_registry):
            if reg_path.startswith(resolved_prefix):
                if not containment_match:
                    containment_match = reg_path
                if hostname_hint and hostname_hint.lower() in reg_path.lower():
                    return reg_path, []
        if containment_match:
            return containment_match, []
        # Hash-based fallback
        if evidence_by_hash:
            for entry in audit_entries:
                entry_inputs = entry.get("input_files", [])
                entry_hashes = entry.get("input_sha256s", [])
                for i, inp in enumerate(entry_inputs):
                    if str(Path(inp).resolve()) == resolved and i < len(entry_hashes):
                        h = entry_hashes[i]
                        if h and h in evidence_by_hash:
                            return evidence_by_hash[h], []
        parent_inputs = output_to_inputs.get(resolved)
        if parent_inputs:
            producer = output_to_entry.get(resolved, {})
            result, sub_chain = _resolve_source_evidence_static(
                parent_inputs,
                audit_entries,
                evidence_registry,
                visited,
                depth + 1,
                max_depth,
                evidence_by_hash,
                output_to_inputs,
                output_to_entry,
                hostname_hint,
            )
            if result:
                step = {
                    "audit_id": producer.get("audit_id", ""),
                    "tool": producer.get("tool", ""),
                    "input_files": producer.get("input_files", []),
                    "role": "intermediate",
                }
                return result, sub_chain + [step]
    return "", []


# --- IOC helpers (extracted to ioc_helpers.py) ---
# Re-exported here so existing callers and tests using
# ``from sift_core.case_manager import _compute_ioc_hash`` keep working.
from sift_core.ioc_helpers import (  # noqa: E402
    _CONF_RANKS,
    _compute_ioc_hash,
    _conf_rank,
    _detect_ioc_type,
    _normalize_ioc,
    _refang_ioc,
)


def _derive_confidence_ceiling(
    provenance: dict,
    finding_prov_grade: str,
    source_evidence: object,
    validated_commands: list,
) -> str:
    """Derive a confidence CEILING from provenance signals (W3 cap-hint).

    Pure function over signals already computed at record_finding time. Returns
    one of HIGH/MEDIUM/LOW/SPECULATIVE. This is a *ceiling*: the caller clamps
    the agent-supplied confidence DOWN to it (``min`` by rank), never up — so a
    self-asserted HIGH citing only NONE/unverified ids gets capped, closing the
    self-asserted-HIGH-on-NONE gap (spec W3.2). It never raises an agent's value.

    Mapping (spec W3.2), re-based on *resolved* ids:
      - HIGH:  FULL grade AND >=2 resolved MCP ids AND no NONE ids.
      - MEDIUM: (FULL AND >=1 resolved MCP id) OR (>=2 resolved MCP/HOOK ids AND
                source_evidence present).
      - LOW:   >=1 resolved (MCP/HOOK) id but below MEDIUM, OR shell-only with
               validated_commands.
      - SPECULATIVE: floor — only none/unverified ids (no resolved provenance).
    """
    mcp = provenance.get("mcp") or []
    hook = provenance.get("hook") or []
    none = provenance.get("none") or []
    n_mcp = len(mcp)
    n_hook = len(hook)
    resolved = n_mcp + n_hook
    has_source = bool(source_evidence)

    # HIGH: strongest — fully-graded, multi-MCP, no unresolved ids.
    if finding_prov_grade == "FULL" and n_mcp >= 2 and len(none) == 0:
        return "HIGH"
    # MEDIUM: fully-graded w/ at least one MCP id, OR two resolved ids backed by
    # traced evidence.
    if (finding_prov_grade == "FULL" and n_mcp >= 1) or (
        resolved >= 2 and has_source
    ):
        return "MEDIUM"
    # LOW: at least one resolved id (but below MEDIUM), or shell-only w/ commands.
    if resolved >= 1 or (validated_commands and resolved == 0):
        return "LOW"
    # Floor: only NONE/unverified ids reached confidence assignment.
    return "SPECULATIVE"


def _validate_case_id(case_id: str) -> None:
    """Validate case_id to prevent path traversal."""
    if not case_id or not case_id.strip():
        raise ValueError("Case ID cannot be empty")
    if "\x00" in case_id:
        raise ValueError("Case ID contains null byte")
    if ".." in case_id or "/" in case_id or "\\" in case_id:
        raise ValueError(f"Invalid case ID (path traversal characters): {case_id}")


def _validate_examiner(examiner: str) -> None:
    """Validate examiner slug: lowercase alphanumeric + hyphens, max 20 chars."""
    if not examiner:
        raise ValueError("Examiner identity cannot be empty")
    if not is_valid_examiner_slug(examiner):
        raise ValueError(
            f"Invalid examiner '{examiner}': must be lowercase alphanumeric + hyphens, max 20 chars"
        )


# MITRE tactic → event_type mapping for auto-created timeline events
_MITRE_EVENT_TYPE = {
    "T10": "execution",  # T1059 etc.
    "T11": "persistence",  # T1136 etc.
    "T12": "execution",  # T1204 etc.
    "T13": "persistence",  # T1353 etc.
    "T14": "execution",  # T1489 etc.
    "T15": "other",  # T15xx varies
    "T1003": "execution",  # Credential Dumping
    "T1021": "lateral",  # Remote Services
    "T1047": "execution",  # WMI
    "T1053": "persistence",  # Scheduled Task
    "T1055": "execution",  # Process Injection
    "T1059": "execution",  # Command Interpreter
    "T1078": "auth",  # Valid Accounts
    "T1098": "persistence",  # Account Manipulation
    "T1110": "auth",  # Brute Force
    "T1190": "network",  # Exploit Public App
    "T1543": "persistence",  # Create/Modify Service
    "T1547": "persistence",  # Boot/Logon Autostart
    "T1548": "execution",  # Abuse Elevation
    "T1562": "other",  # Impair Defenses
    "T1566": "network",  # Phishing
    "T1570": "lateral",  # Lateral Tool Transfer
}


def _infer_event_type(sanitized: dict) -> str:
    """Best-effort event_type from MITRE technique IDs."""
    mitre_ids = sanitized.get("mitre_ids", [])
    if isinstance(mitre_ids, str):
        mitre_ids = [mitre_ids]
    for mid in mitre_ids:
        mid = mid.strip().upper()
        # Try exact match first (T1021), then prefix (T10)
        if mid in _MITRE_EVENT_TYPE:
            return _MITRE_EVENT_TYPE[mid]
        prefix = mid[:3]  # T10, T11, etc.
        if prefix in _MITRE_EVENT_TYPE:
            return _MITRE_EVENT_TYPE[prefix]
    return ""


def build_finding_considerations(finding: dict) -> list[str]:
    """Assemble pre-acceptance guidance for a staged finding."""
    from forensic_knowledge import loader

    considerations: list[str] = []

    framework = loader.get_investigation_framework()
    if framework:
        for item in framework.get("self_check", [])[:5]:
            if isinstance(item, dict):
                text = item.get("question", "")
                how = item.get("how", "")
                considerations.append(f"{text} → {how}" if how else text)
            else:
                considerations.append(item)

    finding_type = finding.get("type", "")
    anti_patterns = loader.get_anti_patterns()
    if finding_type == "attribution":
        for ap in anti_patterns:
            if ap["name"] == "premature_attribution":
                how = ap.get("how_to_avoid", "")
                msg = f"Anti-pattern: {ap['description']}"
                if how:
                    msg += f" How to avoid: {how}"
                considerations.append(msg)
    if finding_type == "exclusion":
        for ap in anti_patterns:
            if ap["name"] == "confirmation_bias":
                how = ap.get("how_to_avoid", "")
                msg = f"Anti-pattern: {ap['description']}"
                if how:
                    msg += f" How to avoid: {how}"
                considerations.append(msg)

    confidence = finding.get("confidence", "").upper()
    confidence_defs = loader.get_confidence_definitions()
    if confidence in confidence_defs:
        cd = confidence_defs[confidence]
        min_ev = cd.get("min_audit_ids", 0)
        if min_ev >= 2:
            considerations.append(
                f"{confidence} confidence requires {min_ev}+ independent corroborating sources "
                f"— are yours truly independent?"
            )

    if finding_type in ("attribution", "exclusion", "conclusion"):
        checkpoint = loader.get_checkpoint(finding_type)
        if checkpoint and isinstance(checkpoint, dict) and "guidance" in checkpoint:
            considerations.append(checkpoint["guidance"])

    return considerations


class CaseManager:
    """Manages forensic investigation cases."""

    def __init__(self) -> None:
        self._active_case_id: str | None = None
        self._active_case_path: Path | None = None

    @property
    def cases_dir(self) -> Path:
        return cases_root()

    @property
    def active_case_dir(self) -> Path | None:
        if self._active_case_path:
            return self._active_case_path
        if not self._active_case_id:
            return None
        return self.cases_dir / self._active_case_id

    @property
    def examiner(self) -> str:
        return resolve_examiner()

    def _require_active_case(self) -> Path:
        db_active = False
        db_case_dir: Path | None = None
        # Catch ONLY ImportError here: the authority-context module being
        # genuinely absent is the single condition under which the legacy file
        # fallback below is permitted. A runtime failure of the authority calls
        # must NOT be swallowed — that would leave db_active=False and fall
        # through to the tamperable SIFT_CASE_DIR / ~/.sift/active_case paths
        # (a fail-OPEN downgrade that violates the DB-authority invariant).
        try:
            from sift_core.active_case_context import (
                current_active_case,
                db_authority_active,
            )
        except ImportError:
            current_active_case = None  # type: ignore[assignment]
            db_authority_active = None  # type: ignore[assignment]

        if current_active_case is not None and db_authority_active is not None:
            # Runtime authority resolution is deliberately OUTSIDE the import
            # guard: any error here propagates so the caller fails CLOSED rather
            # than silently degrading to file-mode active-case authority.
            ctx = current_active_case()
            if ctx and ctx.case_dir is not None and ctx.case_dir.is_dir():
                db_case_dir = ctx.case_dir
                self._active_case_id = ctx.case_key or db_case_dir.name
                self._active_case_path = db_case_dir
            db_active = db_authority_active()

        # BU1: when the authority context resolved a DB case dir, enforce the
        # closed-case safety belt from DB authority (not CASE.yaml) and return it.
        # This is deliberately OUTSIDE the broad ``except`` above: a closed case
        # or a DB error must fail closed (raise), never be swallowed into the
        # tamperable file fallbacks below.
        if db_case_dir is not None:
            self._refuse_closed_case_db()
            return db_case_dir

        # K1: in DB-active mode the active case comes only from the authority
        # context. Never fall back to SIFT_CASE_DIR / ~/.sift/active_case, which
        # are tamperable and could silently steer authoritative work elsewhere.
        if db_active:
            raise ValueError(
                "No active case in authority context. The DB active case could not "
                "be resolved for this request."
            )

        # Check SIFT_CASE_DIR env var first
        from sift_common import resolve_case_dir as _resolve_case_dir_env
        try:
            env_dir_str = _resolve_case_dir_env()
            if env_dir_str:
                case_dir = Path(env_dir_str)
                if case_dir.is_dir() and (case_dir / "CASE.yaml").exists():
                    self._active_case_id = case_dir.name
                    self._active_case_path = case_dir
        except Exception:
            pass

        # Legacy CLI fallback — active_case file check if env var was not set or valid
        if not self._active_case_path or not self._active_case_path.exists():
            active_file = _ACTIVE_CASE_FILE
            if active_file.exists():
                try:
                    content = active_file.read_text().strip()
                except OSError:
                    content = ""
                if content:
                    if os.path.isabs(content):
                        case_dir = Path(content)
                        new_id = case_dir.name
                    else:
                        _validate_case_id(content)
                        case_dir = self.cases_dir / content
                        new_id = content
                    if case_dir.is_dir() and (case_dir / "CASE.yaml").exists():
                        if (
                            new_id != self._active_case_id
                            and self._active_case_id is not None
                        ):
                            logger.info(
                                "Case switched: %s → %s", self._active_case_id, new_id
                            )
                        self._active_case_id = new_id
                        self._active_case_path = case_dir
        d = self.active_case_dir
        if d is None or not d.exists():
            raise ValueError("No active case. Create or select a case in the Examiner Portal first.")
        # Safety belt: refuse closed cases
        meta_file = d / "CASE.yaml"
        if meta_file.exists():
            try:
                meta = yaml.safe_load(meta_file.read_text()) or {}
                if meta.get("status") == "closed":
                    raise ValueError(
                        f"Case {self._active_case_id} is closed. "
                        f"Select an active case in the Examiner Portal to work on a different case."
                    )
            except yaml.YAMLError:
                pass
        return d

    def _effective_examiner(self, override: str = "") -> str:
        """Return override if non-empty, otherwise self.examiner.

        Used by gateway to propagate per-request examiner identity.
        """
        return (
            override.strip().lower() if override and override.strip() else self.examiner
        )

    # --- BATCH-K2: DB investigation authority hooks ---------------------- #

    def _db_case_id(self) -> str | None:
        """Return the Postgres case UUID for the active authority context.

        Only populated in DB-active mode where the Gateway/worker loaded the case
        from Postgres into the :class:`AuthorityContext`. ``case_id`` is the case
        row UUID; ``case_key`` is the human slug.
        """
        try:
            from sift_core.active_case_context import current_active_case

            ctx = current_active_case()
        except Exception:
            return None
        if ctx is None or not ctx.db_active:
            return None
        return ctx.case_id or None

    def _refuse_closed_case_db(self) -> None:
        """Raise if the DB-authoritative case status is closed (BU1).

        Replaces the file CASE.yaml ``status: closed`` safety belt in DB-active
        mode. ``resolve_case_metadata`` returns ``None`` in file mode (so this is
        a no-op there) and raises on a DB failure, so an unverifiable status
        fails closed rather than silently allowing work on a possibly-closed case.
        """
        from sift_core.investigation_store import resolve_case_metadata

        meta = resolve_case_metadata()
        if meta is None:
            return
        if str(meta.get("status", "")).strip().lower() == "closed":
            raise ValueError(
                f"Case {self._active_case_id} is closed. "
                "Select an active case in the Examiner Portal to work on a different case."
            )

    def _investigation_store(self):
        """Return the DB investigation authority store, or None in file mode."""
        try:
            from sift_core.investigation_store import resolve_investigation_store

            return resolve_investigation_store()
        except Exception as exc:  # pragma: no cover - import/connect guard
            logger.warning("investigation store unavailable: %s", exc)
            return None

    def _persist_investigation(self, kind: str, item_id: str, record: dict) -> None:
        """Write an agent-created investigation record to DB authority.

        In DB-active mode this is the authoritative write; the case JSON file is a
        mirror/export only. Fails closed (raises) when the DB write cannot persist
        so a mutating tool never silently degrades to file-only authority.
        """
        case_id = self._db_case_id()
        if not case_id:
            return
        store = self._investigation_store()
        if store is None:
            from sift_core.investigation_store import InvestigationStoreError

            raise InvestigationStoreError(
                "DB authority is active but the investigation store is unavailable; "
                "refusing to record investigation state to files only."
            )
        if kind == "finding":
            store.upsert_finding(case_id, item_id, record)
        elif kind == "timeline":
            store.upsert_timeline_event(case_id, item_id, record)
        elif kind == "ioc":
            store.upsert_ioc(case_id, item_id, record)
        elif kind == "todo":
            store.upsert_todo(case_id, item_id, record)

    # --- AUT2-B3: artifact audit_id validation helpers -------------------- #

    def _candidate_audit_dirs(self, case_dir: Path) -> list[Path]:
        """Every plausible audit dir for this case, deduped.

        The gateway, the durable job worker, and legacy CLI sessions resolve
        their audit JSONL dir independently (state-root keyed by CASE.yaml
        case_id, state-root keyed by directory name, in-case ``audit/``,
        or an explicit ``SIFT_AUDIT_DIR``). Artifact validation must scan all
        of them or a fresh ``run_command`` audit_id written by another process
        is wrongly rejected.
        """
        dirs: list[Path] = []
        seen: set[str] = set()

        def _add(path: Path) -> None:
            key = str(path)
            if key not in seen:
                seen.add(key)
                dirs.append(path)

        _add(case_audit_dir(case_dir))
        _add(state_root(case_dir) / case_dir.name / "audit")
        _add(case_dir / "audit")
        env_audit = os.environ.get("SIFT_AUDIT_DIR", "").strip()
        if env_audit:
            _add(Path(env_audit))
        return dirs

    def _scan_audit_trail(self, case_dir: Path) -> tuple[set[str], list[dict]]:
        """Scan all candidate audit dirs; return (audit_id set, entries).

        Entries are deduped by audit_id across dirs so the downstream
        provenance pass does not see duplicates when the same JSONL is
        reachable through two candidate dirs.
        """
        eid_set: set[str] = set()
        entries: list[dict] = []
        for audit_dir in self._candidate_audit_dirs(case_dir):
            if not audit_dir.is_dir():
                continue
            for jsonl_file in audit_dir.glob("*.jsonl"):
                try:
                    with open(jsonl_file, encoding="utf-8") as f:
                        for line in f:
                            line = line.strip()
                            if not line:
                                continue
                            try:
                                entry = json.loads(line)
                            except json.JSONDecodeError:
                                continue
                            aid = entry.get("audit_id", "")
                            if aid:
                                if aid in eid_set:
                                    continue
                                eid_set.add(aid)
                            entries.append(entry)
                except OSError:
                    continue
        return eid_set, entries

    @staticmethod
    def _audit_id_candidates(aid: str) -> list[str]:
        """Forms of an artifact audit_id to match against the audit trail.

        ``run_command`` returns both the raw audit_id and an ``rc-<audit_id>``
        receipt id; agents legitimately cite either, so match both.
        """
        candidates = [aid]
        if aid.startswith("rc-") and len(aid) > 3:
            candidates.append(aid[3:])
        return candidates

    def _resolve_known_audit_id(self, aid: str, eid_set: set[str]) -> str | None:
        """Return the canonical audit_id if any candidate form is known."""
        for candidate in self._audit_id_candidates(aid):
            if candidate in eid_set:
                return candidate
        return None

    def _db_audit_id_known(self, aid: str) -> bool:
        """Check the DB transport audit (``app.audit_events``) for a tool audit id.

        In DB-active mode the gateway durably records each tool call's
        backend audit id in ``audit_events.details`` (``backend_audit_id``),
        while the local JSONL mirror can lag or land in a different process's
        audit dir. Accept ids the DB authority recorded; fail closed (False)
        on any lookup problem so unknown ids stay rejected.
        """
        try:
            from sift_core.active_case_context import db_authority_active
            from sift_core.investigation_store import control_plane_dsn

            if not db_authority_active():
                return False
            dsn = control_plane_dsn()
            if not dsn:
                return False
            return _db_audit_event_has_audit_id(
                dsn, self._db_case_id(), self._audit_id_candidates(aid)
            )
        except Exception as exc:  # pragma: no cover - defensive
            logger.warning("DB audit-id lookup failed for %s: %s", aid, exc)
            return False

    def get_case_status(self, case_id: str | None = None) -> dict:
        """Get investigation summary.

        BU1: in DB-active mode the case metadata and the finding/timeline/todo
        counters are Postgres authority; CASE.yaml is not read and a DB failure
        fails closed (raises) rather than serving the file mirror.
        """
        from sift_core.investigation_store import resolve_case_metadata

        case_dir = self._resolve_case_dir(case_id)
        manifest = load_manifest(case_dir) or {}
        active_evidence = [f for f in manifest.get("files", []) if f.get("status") != "IGNORED"]

        db_meta = resolve_case_metadata()
        if db_meta is not None:
            meta = db_meta
            store = self._investigation_store()
            db_case_id = self._db_case_id()
            if store is None or not db_case_id:
                from sift_core.investigation_store import InvestigationStoreError

                raise InvestigationStoreError(
                    "DB authority is active but the investigation store is unavailable"
                )
            findings = store.list_findings(db_case_id)
            timeline = store.list_timeline(db_case_id)
            todos = store.list_todos(db_case_id)
        else:
            meta = self._load_case_meta(case_dir)
            findings = self._load_findings(case_dir)
            timeline = self._load_timeline(case_dir)
            todos = self._load_todos(case_dir)

        resp = {
            "case_id": meta["case_id"],
            "name": meta.get("name", ""),
            "status": meta.get("status", "unknown"),
            "examiner": meta.get("examiner", ""),
            "case_brief": build_case_brief(meta),
            "findings": {
                "total": len(findings),
                "draft": sum(1 for f in findings if f.get("status") == "DRAFT"),
                "approved": sum(1 for f in findings if f.get("status") == "APPROVED"),
                "rejected": sum(1 for f in findings if f.get("status") == "REJECTED"),
            },
            "timeline_events": len(timeline),
            "evidence_files": len(active_evidence),
            "todos": {
                "total": len(todos),
                "open": sum(1 for t in todos if t.get("status") == "open"),
                "completed": sum(1 for t in todos if t.get("status") == "completed"),
            },
        }

        # Declaration-driven capability summary: only registered+available
        # backends and the capabilities their manifests advertise (no
        # installed-package probing, no hardcoded add-on names).
        resp.update(build_platform_capabilities())

        return resp

    def list_cases(self) -> list[dict]:
        """List all cases."""
        if not self.cases_dir.exists():
            return []
        results = []
        for case_dir in sorted(self.cases_dir.iterdir()):
            if case_dir.is_dir() and (case_dir / "CASE.yaml").exists():
                meta = self._load_case_meta(case_dir)
                results.append(
                    {
                        "case_id": meta["case_id"],
                        "name": meta.get("name", ""),
                        "status": meta.get("status", "unknown"),
                        "created": meta.get("created", ""),
                        "examiner": meta.get("examiner", ""),
                    }
                )
        return results

    # --- Investigation Records ---

    def record_action(
        self,
        description: str,
        tool: str = "",
        command: str = "",
        examiner_override: str = "",
    ) -> dict:
        """Append action to actions.jsonl."""
        case_dir = self._require_active_case()
        ts = datetime.now(timezone.utc).isoformat()
        exam = self._effective_examiner(examiner_override)

        entry: dict[str, Any] = {
            "ts": ts,
            "description": description,
            "examiner": exam,
        }
        if tool:
            entry["tool"] = tool
        if command:
            entry["command"] = command

        try:
            with open(case_dir / "actions.jsonl", "a", encoding="utf-8") as f:
                f.write(json.dumps(entry) + "\n")
                f.flush()
                os.fsync(f.fileno())
        except OSError as e:
            logger.warning("Failed to write action log: %s", e)
            return {"status": "write_failed", "timestamp": ts, "error": str(e)}

        return {"status": "recorded", "timestamp": ts}

    def record_finding(
        self,
        finding: dict,
        examiner_override: str = "",
        supporting_commands: list[dict] | None = None,
        artifacts: list[dict] | None = None,
        audit: Any | None = None,
    ) -> dict:
        """Validate and stage finding as DRAFT.

        Args:
            finding: Finding data dict.
            examiner_override: Override examiner identity.
            supporting_commands: List of shell commands that produced evidence.
                Each dict must have command, output_excerpt, purpose.
            audit: AuditWriter instance (needed for shell audit ID generation).
        """
        case_dir = self._require_active_case()

        # Validate via discipline module
        validation = validate_finding_data(finding)
        if not validation.get("valid", False):
            return {
                "status": "VALIDATION_FAILED",
                "errors": validation.get("errors", []),
            }
        # Carry forward validation warnings
        validation_warnings = validation.get("warnings", [])

        exam = self._effective_examiner(examiner_override)

        # Auto-extract supporting_commands/artifacts if LLM passed them inline
        if supporting_commands is None and isinstance(
            finding.get("supporting_commands"), list
        ):
            supporting_commands = finding.pop("supporting_commands")
        if artifacts is None and isinstance(finding.get("artifacts"), list):
            artifacts = finding.pop("artifacts")

        findings = self._load_findings(case_dir)
        seq = _next_seq(findings, "id", "F", exam)
        finding_id = f"F-{exam}-{seq:03d}"
        now = datetime.now(timezone.utc).isoformat()
        today = datetime.now(timezone.utc).strftime("%Y%m%d")

        # Allowlist: only accepted fields pass through from user input
        sanitized = {k: v for k, v in finding.items() if k in _ALLOWED_FINDING_FIELDS}

        # supersedes: native self-correction chain (e.g. F-006 supersedes
        # F-003) instead of overloading related_findings. Accept a single id or
        # a list of ids; normalize to a deduped list of trimmed strings.
        if "supersedes" in sanitized:
            raw_sup = sanitized["supersedes"]
            if isinstance(raw_sup, str):
                raw_sup = [raw_sup]
            if isinstance(raw_sup, list):
                seen_sup: set[str] = set()
                norm_sup: list[str] = []
                for sid in raw_sup:
                    sid = str(sid).strip()[:128]
                    if sid and sid not in seen_sup:
                        seen_sup.add(sid)
                        norm_sup.append(sid)
                sanitized["supersedes"] = norm_sup
            else:
                del sanitized["supersedes"]

        # Truncate string fields with explicit limits.
        # host is uppercased so aggregation by host doesn't split on casing.
        if sanitized.get("host"):
            sanitized["host"] = str(sanitized["host"]).strip()[:200].upper()
        if sanitized.get("affected_account"):
            sanitized["affected_account"] = str(sanitized["affected_account"])[:200]

        # Process supporting_commands — generate shell audit IDs
        shell_audit_ids: list[str] = []
        validated_commands: list[dict] = []
        audit_warnings: list[str] = []
        if supporting_commands:
            for _i, cmd in enumerate(supporting_commands[:5]):
                if not isinstance(cmd, dict):
                    continue
                command = cmd.get("command", "")
                output_excerpt = cmd.get("output_excerpt", "")
                purpose = cmd.get("purpose", "")
                if not command or not purpose:
                    continue
                # Truncate output_excerpt
                if len(output_excerpt) > 2000:
                    output_excerpt = output_excerpt[:2000]
                
                cmd_audit_id = cmd.get("audit_id", "").strip()
                if cmd_audit_id:
                    shell_eid = cmd_audit_id
                else:
                    shell_seq = self._next_shell_seq(case_dir, exam, today)
                    shell_eid = f"shell-{exam}-{today}-{shell_seq:03d}"
                
                shell_audit_ids.append(shell_eid)
                validated_cmd = {
                    "command": command,
                    "output_excerpt": output_excerpt,
                    "purpose": purpose,
                    "audit_id": shell_eid,
                }
                validated_commands.append(validated_cmd)
                # Write audit entry for this shell command
                if audit:
                    logged_id = audit.log(
                        tool="supporting_command",
                        params={"command": command, "purpose": purpose},
                        result_summary={"output_excerpt": output_excerpt[:200]},
                        source="shell_self_report",
                        audit_id=shell_eid,
                    )
                    if logged_id is None:
                        audit_warnings.append(
                            f"Audit write failed for shell evidence {shell_eid}"
                        )
                # B-D3: in DB-active mode the shell-* id is minted here and never
                # seen by the gateway envelope, so a finding that cites it would
                # dangle in the DB-mode portal panel. Forward-write a citable
                # app.audit_events row keyed by shell_eid (case-scoped to the
                # case UUID). Best-effort: never block record_finding.
                _db_case_uuid = self._db_case_id()
                if _db_case_uuid:
                    try:
                        _persist_shell_audit_event(
                            shell_eid,
                            command=command,
                            purpose=purpose,
                            case_id=_db_case_uuid,
                            examiner=exam,
                        )
                    except Exception as exc:  # noqa: BLE001 — fail-soft
                        logger.debug(
                            "shell audit_events forward-write skipped for %s: %s",
                            shell_eid,
                            type(exc).__name__,
                        )
                        audit_warnings.append(
                            f"DB audit write failed for shell evidence {shell_eid}"
                        )

        # Validate artifacts — parameter wins over finding dict (dedup)
        validated_artifacts: list[dict] = []
        raw_artifacts = (
            artifacts if artifacts is not None else sanitized.get("artifacts", [])
        )
        if isinstance(raw_artifacts, str):
            try:
                raw_artifacts = json.loads(raw_artifacts)
            except (json.JSONDecodeError, TypeError):
                raw_artifacts = []
        if isinstance(raw_artifacts, list):
            for art in raw_artifacts[:10]:
                if not isinstance(art, dict):
                    continue
                source = art.get("source", "").strip()
                extraction = art.get("extraction", "").strip()
                content = art.get("content", "").strip()
                if not content:
                    content = art.get("raw_data", "").strip()
                if not source or not extraction or not content:
                    continue
                validated_artifacts.append(
                    {
                        "source": source[:500],
                        "extraction": extraction[:2000],
                        "content": content[:5000],
                        "content_type": str(art.get("content_type", ""))[:50],
                        "purpose": str(art.get("purpose", ""))[:500],
                        "audit_id": str(art.get("audit_id", ""))[:100],
                        "output_ref": str(art.get("output_ref", ""))[:500],
                    }
                )
        if validated_artifacts:
            sanitized["artifacts"] = validated_artifacts
        else:
            sanitized.pop("artifacts", None)
        dropped_artifact_count = (
            len(raw_artifacts) - len(validated_artifacts)
            if isinstance(raw_artifacts, list)
            else 0
        )

        # Validate artifact audit_ids: required and must exist in audit trail
        # (JSONL mirror across all plausible audit dirs) OR in the DB transport
        # audit authority (app.audit_events) in DB-active mode.
        provenance_warnings: list[str] = []
        if validated_artifacts:
            eid_set, all_audit_entries = self._scan_audit_trail(case_dir)

            for art in validated_artifacts:
                aid = art.get("audit_id", "")
                if not aid:
                    return {
                        "status": "REJECTED",
                        "error": (
                            "Artifact missing audit_id — pass the audit_id "
                            "from the tool response (use supporting_commands "
                            "to record Bash commands with audit_ids)."
                        ),
                    }
                resolved_aid = self._resolve_known_audit_id(aid, eid_set)
                if resolved_aid is None:
                    # Two-strike: flush race condition — rescan everything
                    time.sleep(0.1)
                    eid_set, all_audit_entries = self._scan_audit_trail(case_dir)
                    resolved_aid = self._resolve_known_audit_id(aid, eid_set)
                if resolved_aid is None and self._db_audit_id_known(aid):
                    # DB audit authority recorded this tool call even though the
                    # local JSONL mirror has not caught up (cross-process lag).
                    resolved_aid = aid[3:] if aid.startswith("rc-") else aid
                if resolved_aid is None:
                    recent_ids = [
                        e.get("audit_id")
                        for e in all_audit_entries
                        if e.get("audit_id")
                    ][-3:]
                    hint = (
                        f" Recent valid audit_ids: {', '.join(recent_ids)}."
                        if recent_ids
                        else ""
                    )
                    return {
                        "status": "REJECTED",
                        "error": (
                            f"audit_id '{aid}' not found in audit trail. "
                            "Pass the audit_id from the tool response." + hint
                        ),
                    }
                # Canonicalize (e.g. strip rc- receipt prefix) so downstream
                # provenance resolution matches the JSONL trail entries.
                art["audit_id"] = resolved_aid

            # Auto-merge artifact audit_ids into finding audit_ids
            artifact_aids = [
                a["audit_id"] for a in validated_artifacts if a.get("audit_id")
            ]
        else:
            artifact_aids = []
            all_audit_entries = []

        # Extend audit_ids with shell audit IDs + artifact audit IDs
        audit_ids = list(sanitized.get("audit_ids", []))
        audit_ids.extend(shell_audit_ids)
        audit_ids.extend(artifact_aids)
        sanitized["audit_ids"] = list(dict.fromkeys(audit_ids))

        # Per-artifact provenance resolution
        finding_prov_grade = "PARTIAL"
        if all_audit_entries and validated_artifacts:
            # In DB-authority mode the on-disk evidence.json is empty ([]); the
            # real sealed-evidence registry lives in Postgres.  Load from DB when
            # active so confidence grading and the artifact-source hard-reject
            # both see the actual sealed evidence set.  File mode keeps the
            # existing load_manifest() path.  Fails closed (empty list) on any
            # DB error — identical to the legacy behaviour when no files are
            # registered (PARTIAL grade, artifact rejected).
            try:
                from sift_core.active_case_context import db_authority_active
                from sift_core.investigation_store import list_sealed_evidence_db

                if db_authority_active():
                    evidence = list_sealed_evidence_db(self._db_case_id() or "")
                else:
                    manifest = load_manifest(case_dir) or {}
                    evidence = manifest.get("files", [])
            except Exception:
                manifest = load_manifest(case_dir) or {}
                evidence = manifest.get("files", [])
            registered = set()
            ev_by_hash = {}
            for e in evidence:
                if e.get("status") in ("IGNORED", "RETIRED"):
                    continue
                p = e.get("path", "")
                if p:
                    resolved_p = str(Path(p).resolve()) if str(p).startswith("/") else str((case_dir / p).resolve())
                    registered.add(resolved_p)
                    h = e.get("sha256", "")
                    if h:
                        ev_by_hash[h] = resolved_p
            audit_by_id: dict[str, dict] = {}
            for e in all_audit_entries:
                aid_key = e.get("audit_id", "")
                if not aid_key:
                    continue
                if aid_key in audit_by_id:
                    logger.warning("Duplicate audit_id in trail: %s", aid_key)
                audit_by_id[aid_key] = e
            active_cid = self._active_case_id or ""

            # Pre-build output→input and output→entry lookups
            shared_output_map: dict[str, list[str]] = {}
            shared_entry_map: dict[str, dict] = {}
            for _e in all_audit_entries:
                _inp = _e.get("input_files", [])
                _rs = _e.get("result_summary", {})
                if isinstance(_rs, dict):
                    _of = _rs.get("output_file", "")
                    if _of:
                        try:
                            _key = str(Path(_of).resolve())
                            shared_output_map[_key] = _inp
                            shared_entry_map[_key] = _e
                        except OSError:
                            pass
                    for _of in _rs.get("output_files", []):
                        if _of:
                            try:
                                _key = str(Path(_of).resolve())
                                shared_output_map[_key] = _inp
                                shared_entry_map[_key] = _e
                            except OSError:
                                pass

            for art in validated_artifacts:
                art_aid = art.get("audit_id", "")
                if not art_aid:
                    art["provenance_grade"] = "PARTIAL"
                    continue
                entry = audit_by_id.get(art_aid)
                if not entry:
                    art["provenance_grade"] = "PARTIAL"
                    continue

                # Direct path: audit entry has input_files
                art_input_files = entry.get("input_files", [])
                if art_input_files:
                    try:
                        source_ev, chain = _resolve_source_evidence_static(
                            art_input_files,
                            all_audit_entries,
                            registered,
                            evidence_by_hash=ev_by_hash,
                            output_to_inputs=shared_output_map,
                            output_to_entry=shared_entry_map,
                        )
                        if source_ev:
                            art["source_evidence"] = source_ev
                            art["provenance_grade"] = "FULL"
                            if chain:
                                art["provenance_chain"] = chain
                            else:
                                art["provenance_chain"] = [
                                    {
                                        "audit_id": entry.get("audit_id", ""),
                                        "tool": entry.get("tool", ""),
                                        "input_files": entry.get("input_files", []),
                                        "role": "query",
                                    }
                                ]
                            continue
                    except OSError:
                        pass

                # Indirect path: opensearch_search/opensearch_aggregate → trace to opensearch_ingest
                tool = entry.get("tool", "")
                if tool.startswith("idx_"):
                    search_index = entry.get("params", {}).get("index", "")
                    # Collect candidates, score by filename affinity
                    candidates: list[tuple[int, dict, list[str]]] = []
                    for e in all_audit_entries:
                        e_tool = e.get("tool", "")
                        if not (
                            e_tool.startswith("opensearch_ingest") and e.get("input_files")
                        ):
                            continue
                        e_cid = e.get("case_id", "")
                        if e_cid and active_cid and e_cid != active_cid:
                            continue
                        ingest_hosts: list[str] = []
                        if search_index and "*" not in search_index:
                            ingest_hosts = e.get("params", {}).get("hosts", [])
                            if not ingest_hosts:
                                h = e.get("params", {}).get("hostname", "")
                                if h:
                                    ingest_hosts = [h]
                            idx_lower = search_index.lower()
                            if not ingest_hosts or not any(
                                idx_lower.endswith(f"-{h.lower()}")
                                or f"-{h.lower()}-" in idx_lower
                                for h in ingest_hosts
                            ):
                                continue
                        score = 0
                        for inp in e.get("input_files", []):
                            stem = Path(inp).stem.lower()
                            if stem and search_index and stem in search_index.lower():
                                score = 1
                                break
                        candidates.append((score, e, ingest_hosts))
                    candidates.sort(key=lambda c: -c[0])
                    for _score, e, ingest_hosts in candidates:
                        hint = ingest_hosts[0] if ingest_hosts else ""
                        try:
                            source_ev, chain = _resolve_source_evidence_static(
                                e["input_files"],
                                all_audit_entries,
                                registered,
                                evidence_by_hash=ev_by_hash,
                                output_to_inputs=shared_output_map,
                                output_to_entry=shared_entry_map,
                                hostname_hint=hint,
                            )
                            if source_ev:
                                art["source_evidence"] = source_ev
                                # Extract artifact type from index name.
                                # The `case-` prefix is applied exactly once: the
                                # case key (dir basename) already starts with
                                # `case-`, so strip the redundant leading prefix
                                # before matching the single-prefix index name
                                # (mirrors opensearch_mcp index naming, XYE-10).
                                # Inlined to avoid a sift-core -> opensearch-mcp dep.
                                _art_type = ""
                                if search_index and active_cid:
                                    _key = (
                                        active_cid[len("case-") :]
                                        if active_cid.lower().startswith("case-")
                                        else active_cid
                                    )
                                    _pfx = f"case-{_key}-".lower()
                                    _idx = search_index.lower()
                                    if _idx.startswith(_pfx):
                                        _rem = _idx[len(_pfx) :]
                                        if hint:
                                            _sfx = f"-{hint}".lower()
                                            if _rem.endswith(_sfx):
                                                _art_type = _rem[: -len(_sfx)]
                                        # Wildcard: strip trailing -* or just use remainder
                                        if not _art_type:
                                            _art_type = _rem.rstrip("-*")
                                ingest_step = {
                                    "audit_id": e.get("audit_id"),
                                    "tool": e.get("tool"),
                                    "input_files": e.get("input_files"),
                                    "hostname": hint
                                    or (
                                        e.get("params", {}).get("hosts", [""])[0]
                                        if e.get("params", {}).get("hosts")
                                        else e.get("params", {}).get("hostname", "")
                                    ),
                                    "artifact_type": _art_type,
                                    "role": "ingest",
                                }
                                # Find per-artifact parser entry via run_id
                                ingest_run_id = e.get("params", {}).get("run_id", "")
                                parser_step = None
                                if ingest_run_id and search_index:
                                    idx_lower = search_index.lower()
                                    for pe in all_audit_entries:
                                        pe_tool = pe.get("tool", "")
                                        if not pe_tool.startswith("ingest_"):
                                            continue
                                        pe_rid = pe.get("params", {}).get("run_id", "")
                                        if pe_rid != ingest_run_id:
                                            continue
                                        pe_host = pe.get("params", {}).get(
                                            "hostname", ""
                                        )
                                        if (
                                            hint
                                            and pe_host
                                            and pe_host.lower() != hint.lower()
                                        ):
                                            continue
                                        # Match artifact type from index name
                                        pe_idx = (
                                            pe.get("params", {})
                                            .get("index_name", "")
                                            .lower()
                                        )
                                        if pe_idx and pe_idx in idx_lower:
                                            parser_step = {
                                                "audit_id": pe.get("audit_id"),
                                                "tool": pe_tool,
                                                "hostname": pe_host,
                                                "role": "parser",
                                            }
                                            break
                                full_chain = chain + [ingest_step]
                                if parser_step:
                                    full_chain.append(parser_step)
                                art["provenance_chain"] = full_chain
                                art["provenance_grade"] = "FULL"
                                break
                        except OSError:
                            continue

                if "provenance_grade" not in art:
                    art["provenance_grade"] = "PARTIAL"

                # Ensure the terminal "query" step (the tool that produced
                # this artifact's data) is present in the chain. Path A
                # builds chains that may include it; Path B/D builds
                # chains without it. Normalizing server-side means the
                # portal reads what the server provides — no per-render
                # synthesis.
                art_aid = art.get("audit_id", "")
                chain = art.get("provenance_chain") or []
                if art_aid and not any(s.get("audit_id") == art_aid for s in chain):
                    art["provenance_chain"] = chain + [
                        {"audit_id": art_aid, "tool": "", "role": "query"}
                    ]

            # Finding-level grade: FULL or PARTIAL (NONE cannot survive reject gates)
            art_grades = [
                a.get("provenance_grade", "PARTIAL") for a in validated_artifacts
            ]
            if all(g == "FULL" for g in art_grades):
                finding_prov_grade = "FULL"
            else:
                finding_prov_grade = "PARTIAL"
            for art in validated_artifacts:
                if art.get("source_evidence"):
                    sanitized["source_evidence"] = art["source_evidence"]
                    break

            # Hard reject: artifact sources must be in evidence registry.
            # Exception: FULL-graded artifacts (chain traced to evidence).
            unregistered_sources = []
            for art in validated_artifacts:
                if art.get("provenance_grade") == "FULL":
                    continue
                src = art.get("source", "")
                if not src:
                    continue
                try:
                    resolved = str(Path(src).resolve()) if str(src).startswith("/") else str((case_dir / src).resolve())
                except OSError:
                    continue
                if resolved not in registered:
                    prefix = resolved.rstrip("/") + "/"
                    if any(r.startswith(prefix) for r in registered):
                        continue
                    case_dir_str = str(case_dir)
                    case_relative = src
                    if resolved.startswith(case_dir_str + "/"):
                        case_relative = resolved[len(case_dir_str) + 1 :]
                    unregistered_sources.append(
                        {
                            "source": src,
                            "action": f"evidence_register(path='{case_relative}')",
                        "hint": (
                            "If derivative: pass supporting_commands with "
                            "audit_ids linking to the original evidence."
                        ),
                        }
                    )
            if unregistered_sources:
                fid = sanitized.get("finding_id", "unknown")
                return {
                    "status": "REJECTED",
                    "error": (
                        "Artifact sources not in evidence registry. "
                        "Register original evidence via the portal, or bridge "
                        "derivatives to registered evidence with supporting_commands."
                    ),
                    "unregistered_sources": unregistered_sources,
                    "finding_held": f"{fid} (not staged -- fix sources and resubmit)",
                }

            # Provenance gap diagnostics for staged findings
            provenance_gaps: list[dict] = []
            for i, art in enumerate(validated_artifacts):
                if art.get("provenance_grade") == "FULL":
                    continue
                art_aid = art.get("audit_id", "")
                entry = audit_by_id.get(art_aid, {}) if art_aid else {}
                unresolved = ""
                for inp in entry.get("input_files", []):
                    try:
                        r = str(Path(inp).resolve())
                    except OSError:
                        r = inp
                    if r not in registered:
                        unresolved = inp
                        break
                gap: dict = {
                    "artifact_index": i,
                    "audit_id": art_aid or "(none)",
                    "grade": art.get("provenance_grade", "PARTIAL"),
                }
                if unresolved:
                    gap["unresolved_input"] = unresolved
                gap["fix"] = (
                    "Link to registered evidence with supporting_commands "
                    "and resubmit"
                )
                provenance_gaps.append(gap)
            if provenance_gaps:
                sanitized["provenance_gaps"] = provenance_gaps

        if provenance_warnings:
            sanitized["provenance_warnings"] = provenance_warnings

        # Classify provenance
        provenance = self._classify_provenance(sanitized["audit_ids"], case_dir)

        # Hard gate: reject if all NONE and no supporting_commands
        if provenance["summary"] == "NONE" and not validated_commands:
            return {
                "status": "REJECTED",
                "error": (
                    "Finding rejected: no evidence trail. Every finding needs provenance. "
                    "Options: (1) Pass audit_ids from MCP tool responses. "
                    "(2) Pass supporting_commands as a SEPARATE PARAMETER (not inside the finding dict) "
                    "with command, purpose, and output_excerpt for each shell command used. "
                    "(3) For analytical findings without tool evidence, use "
                    "command='analytical reasoning' in supporting_commands."
                ),
            }

        # Provenance grade: per-artifact roll-up, or shell fallback
        if not validated_artifacts:
            finding_prov_grade = "PARTIAL"  # shell-only (no artifacts)

        # W3 cap-hint: clamp the agent-supplied confidence DOWN to a ceiling
        # derived from resolved provenance. Provenance may only LOWER the
        # agent's value, never raise it (final = weaker of the two by rank).
        # NEW findings only — confidence is inside the content hash, so this MUST
        # run before _compute_content_hash and is never backfilled onto existing
        # findings (that would mutate their hash and break the approval ledger).
        agent_conf = (sanitized.get("confidence") or "").upper()
        derived_ceiling = _derive_confidence_ceiling(
            provenance,
            finding_prov_grade,
            sanitized.get("source_evidence"),
            validated_commands,
        )
        # min() by rank = the WEAKER of the two (higher rank number).
        final_conf = (
            agent_conf
            if _conf_rank(agent_conf) >= _conf_rank(derived_ceiling)
            else derived_ceiling
        )
        clamped = final_conf != agent_conf
        sanitized["confidence"] = final_conf
        confidence_derivation = {
            "agent": agent_conf,
            "derived_ceiling": derived_ceiling,
            "final": final_conf,
            "clamped": clamped,
            "basis": {
                "prov_grade": finding_prov_grade,
                "mcp_ids": len(provenance.get("mcp") or []),
                "hook_ids": len(provenance.get("hook") or []),
                "none_ids": len(provenance.get("none") or []),
            },
        }
        if clamped:
            audit_warnings.append(
                f"confidence capped {agent_conf}->{final_conf}: "
                f"{len(provenance.get('mcp') or [])} resolved MCP ids, "
                f"prov_grade={finding_prov_grade}"
            )

        finding_record = {
            **sanitized,
            "confidence_derivation": confidence_derivation,
            "id": finding_id,
            "status": "DRAFT",
            "staged": now,
            "modified_at": now,
            "created_by": exam,
            "examiner": exam,
            "provenance": provenance["summary"],
            "provenance_detail": provenance,
            "provenance_grade": finding_prov_grade,
        }

        # Store supporting_commands if provided
        if validated_commands:
            finding_record["supporting_commands"] = validated_commands

        # Response warnings (accumulated through remaining steps)
        warnings: list[str] = []

        # Auto-create timeline event for type=finding with event_timestamp
        timeline_event_id = ""
        finding_type = sanitized.get("type", "")
        event_ts = sanitized.get("event_timestamp", "")
        if finding_type == "finding" and event_ts:
            timeline = self._load_timeline(case_dir)
            tl_seq = _next_seq(timeline, "id", "T", exam)
            timeline_event_id = f"T-{exam}-{tl_seq:03d}"
            finding_record["timeline_event_id"] = timeline_event_id
        # Warning for missing event_timestamp handled by validation.py
        # (validation_warnings already added to warnings list)

        # Compute content hash at staging
        finding_record["content_hash"] = _compute_content_hash(finding_record)

        # K2: DB authority write first in DB-active mode (fails closed). The case
        # JSON file is a mirror/export only and cannot be the authority source.
        self._persist_investigation("finding", finding_id, finding_record)
        findings.append(finding_record)
        self._save_findings(case_dir, findings)

        # Create auto-linked timeline event (try/except — never blocks finding)
        if timeline_event_id:
            try:
                tl_event = {
                    "id": timeline_event_id,
                    "timestamp": event_ts,
                    "description": sanitized.get("title", ""),
                    "source": sanitized.get("source_evidence", "")
                    or sanitized.get("artifact_ref", "")
                    or (
                        sanitized.get("audit_ids", [""])[0]
                        if sanitized.get("audit_ids")
                        else ""
                    ),
                    "event_type": sanitized.get("event_type")
                    or _infer_event_type(sanitized)
                    or "other",
                    "related_findings": [finding_id],
                    "auto_created_from": finding_id,
                    "status": "DRAFT",
                    "staged": now,
                    "modified_at": now,
                    "created_by": exam,
                    "examiner": exam,
                    "audit_ids": list(sanitized.get("audit_ids", [])),
                }
                tl_event["content_hash"] = _compute_content_hash(tl_event)
                self._persist_investigation("timeline", timeline_event_id, tl_event)
                timeline.append(tl_event)
                self._save_timeline(case_dir, timeline)
            except Exception as exc:
                logger.warning("Auto-timeline creation failed: %s", exc)
                warnings.append(f"Timeline auto-creation failed: {exc}")

        # IOC auto-extraction (try/except — never blocks finding save)
        iocs_extracted = 0
        try:
            iocs_extracted = self._process_iocs(finding_record, case_dir)
        except Exception as exc:
            logger.warning("IOC processing failed: %s", exc)
            warnings.append(f"IOC processing failed: {exc}")

        # IOC completeness check — warn if text mentions IOCs not in the list
        try:
            text = (
                f"{finding.get('observation', '')} {finding.get('interpretation', '')}"
            )
            submitted = {
                str(i).lower().strip()
                for i in (finding.get("iocs") or [])
                if isinstance(i, str)
            }
            mentioned_ips = set(
                re.findall(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", text)
            )
            mentioned_hashes = set(re.findall(r"\b[a-fA-F0-9]{32,64}\b", text))
            missing = (mentioned_ips | mentioned_hashes) - submitted
            if missing:
                warnings.append(
                    f"IOC completeness: {len(missing)} value(s) in text but not in iocs list: "
                    + ", ".join(sorted(missing)[:5])
                )
        except Exception:
            pass

        result = {
            "status": "STAGED",
            "finding_id": finding_id,
            "provenance_detail": provenance,
            "provenance_grade": finding_prov_grade,
            "source_evidence": sanitized.get("source_evidence", ""),
        }
        gaps = sanitized.get("provenance_gaps", [])
        if gaps:
            result["provenance_gaps"] = gaps
            result["message"] = (
                f"Finding staged as {finding_prov_grade}. "
                f"{len(gaps)} artifact(s) have provenance gaps. "
                "Fix gaps and resubmit to upgrade to FULL."
            )
        if timeline_event_id:
            result["timeline_event_id"] = timeline_event_id
        if sanitized.get("supersedes"):
            result["supersedes"] = sanitized["supersedes"]
        if iocs_extracted:
            result["iocs_extracted"] = iocs_extracted
        if dropped_artifact_count > 0:
            warnings.append(
                f"{dropped_artifact_count} artifact(s) dropped — each artifact requires "
                "source, extraction, and content fields (not raw_data)."
            )
        dropped_cmd_count = (
            len(supporting_commands) - len(validated_commands)
            if supporting_commands
            else 0
        )
        if dropped_cmd_count > 0:
            warnings.append(
                f"{dropped_cmd_count} supporting_command(s) dropped (missing command or purpose)"
            )
        warnings.extend(audit_warnings)
        warnings.extend(validation_warnings)
        if warnings:
            result["warning"] = " ".join(warnings)
        return result

    def _next_shell_seq(self, case_dir: Path, examiner: str, today: str) -> int:
        """Find next sequence number for shell-{examiner}-{today}-NNN audit IDs."""
        audit_dir = case_audit_dir(case_dir)
        prefix = f"shell-{examiner}-{today}-"
        max_num = 0
        if audit_dir.is_dir():
            for jsonl_file in audit_dir.glob("*.jsonl"):
                try:
                    with open(jsonl_file, encoding="utf-8") as f:
                        for line in f:
                            line = line.strip()
                            if not line:
                                continue
                            try:
                                entry = json.loads(line)
                                eid = entry.get("audit_id", "")
                                if eid.startswith(prefix):
                                    try:
                                        num = int(eid[len(prefix) :])
                                        max_num = max(max_num, num)
                                    except ValueError:
                                        pass
                            except json.JSONDecodeError:
                                continue
                except OSError:
                    continue
        return max_num + 1

    def record_timeline_event(self, event: dict, examiner_override: str = "") -> dict:
        """Validate and stage timeline event as DRAFT."""
        case_dir = self._require_active_case()

        # Basic validation — aligned with tool schema (title, timestamp, description, host, source)
        required = ["title", "timestamp", "description", "host", "source"]
        missing = [k for k in required if not event.get(k)]
        if missing:
            return {
                "status": "VALIDATION_FAILED",
                "errors": [f"Missing required fields: {missing}"],
            }

        exam = self._effective_examiner(examiner_override)
        timeline = self._load_timeline(case_dir)
        seq = _next_seq(timeline, "id", "T", exam)
        event_id = f"T-{exam}-{seq:03d}"
        now = datetime.now(timezone.utc).isoformat()

        # Strip protected fields from user input for defense-in-depth
        sanitized = {k: v for k, v in event.items() if k not in _PROTECTED_EVENT_FIELDS}
        event_record = {
            **sanitized,
            "id": event_id,
            "status": "DRAFT",
            "staged": now,
            "modified_at": now,
            "created_by": exam,
            "examiner": exam,
        }
        event_record["content_hash"] = _compute_content_hash(event_record)
        self._persist_investigation("timeline", event_id, event_record)
        timeline.append(event_record)
        self._save_timeline(case_dir, timeline)

        return {"status": "STAGED", "event_id": event_id}

    def get_findings(self, status: str | None = None) -> list[dict]:
        """Return local findings."""
        case_dir = self._require_active_case()
        findings = self._load_findings(case_dir)
        if status:
            findings = [f for f in findings if f.get("status") == status.upper()]
        return findings

    def get_timeline(
        self,
        status: str | None = None,
        source: str | None = None,
        examiner: str | None = None,
        start_date: str | None = None,
        end_date: str | None = None,
        event_type: str | None = None,
    ) -> list[dict]:
        """Return local timeline, sorted chronologically.

        Optional filters narrow the result set:
        - status: DRAFT, APPROVED, REJECTED
        - source: substring match against event source field
        - examiner: exact match against examiner field
        - start_date: ISO date/datetime lower bound on timestamp
        - end_date: ISO date/datetime upper bound on timestamp
        - event_type: exact match against event_type field
        """
        case_dir = self._require_active_case()
        events = self._load_timeline(case_dir)
        events.sort(key=lambda t: t.get("timestamp", ""))
        if status:
            events = [e for e in events if e.get("status") == status.upper()]
        if source:
            events = [
                e for e in events if source.lower() in e.get("source", "").lower()
            ]
        if examiner:
            events = [e for e in events if e.get("examiner") == examiner]
        if start_date:
            events = [e for e in events if e.get("timestamp", "") >= start_date]
        if end_date:
            events = [e for e in events if e.get("timestamp", "") <= end_date]
        if event_type:
            events = [e for e in events if e.get("event_type", "") == event_type]
        return events

    def get_actions(self, limit: int = 50) -> list[dict]:
        """Return recent actions from actions.jsonl."""
        case_dir = self._require_active_case()
        entries = []
        actions_file = case_dir / "actions.jsonl"
        if actions_file.exists():
            try:
                with open(actions_file, encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if line:
                            try:
                                entries.append(json.loads(line))
                            except json.JSONDecodeError:
                                logger.warning("Corrupt JSONL line in %s", actions_file)
            except OSError as e:
                logger.warning("Failed to read actions file %s: %s", actions_file, e)
        entries.sort(key=lambda e: e.get("ts", ""))
        return entries[-limit:]

    # --- TODOs ---

    def add_todo(
        self,
        description: str,
        assignee: str = "",
        priority: str = "medium",
        related_findings: list[str] | None = None,
        examiner_override: str = "",
    ) -> dict:
        """Create a new TODO item."""
        case_dir = self._require_active_case()
        exam = self._effective_examiner(examiner_override)
        todos = self._load_todos(case_dir)
        seq = _next_seq(todos, "todo_id", "TODO", exam)
        todo_id = f"TODO-{exam}-{seq:03d}"

        todo = {
            "todo_id": todo_id,
            "description": description,
            "status": "open",
            "priority": priority if priority in ("high", "medium", "low") else "medium",
            "assignee": assignee,
            "related_findings": related_findings or [],
            "created_by": exam,
            "examiner": exam,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "notes": [],
            "completed_at": None,
        }
        self._persist_investigation("todo", todo_id, todo)
        todos.append(todo)
        self._save_todos(case_dir, todos)

        return {"status": "created", "todo_id": todo_id}

    def list_todos(self, status: str = "open", assignee: str = "") -> list[dict]:
        """List local TODOs, filtered by status and/or assignee."""
        case_dir = self._require_active_case()
        todos = self._load_todos(case_dir)

        if status != "all":
            todos = [t for t in todos if t.get("status") == status]
        if assignee:
            todos = [t for t in todos if t.get("assignee") == assignee]

        return todos

    def update_todo(
        self,
        todo_id: str,
        status: str = "",
        note: str = "",
        assignee: str = "",
        priority: str = "",
        examiner_override: str = "",
    ) -> dict:
        """Update a TODO item."""
        case_dir = self._require_active_case()
        todos = self._load_todos(case_dir)
        exam = self._effective_examiner(examiner_override)

        for todo in todos:
            if todo["todo_id"] == todo_id:
                if status and status in ("open", "completed"):
                    todo["status"] = status
                    if status == "completed":
                        todo["completed_at"] = datetime.now(timezone.utc).isoformat()
                if assignee:
                    todo["assignee"] = assignee
                if priority and priority in ("high", "medium", "low"):
                    todo["priority"] = priority
                if note:
                    todo["notes"].append(
                        {
                            "note": note,
                            "by": exam,
                            "at": datetime.now(timezone.utc).isoformat(),
                        }
                    )
                self._persist_investigation("todo", todo_id, todo)
                self._save_todos(case_dir, todos)
                return {"status": "updated", "todo_id": todo_id}

        return {"status": "not_found", "todo_id": todo_id}

    def complete_todo(self, todo_id: str, examiner_override: str = "") -> dict:
        """Mark a TODO as completed."""
        result = self.update_todo(
            todo_id, status="completed", examiner_override=examiner_override
        )
        if result.get("status") == "updated":
            result["status"] = "completed"
        return result

    # --- Evidence ---

    def list_evidence(self) -> list[dict]:
        case_dir = self._require_active_case()
        return list_manifest_evidence_data(case_dir).get("evidence", [])

    # --- Grounding Score ---

    def _score_grounding(self, finding: dict) -> dict:
        """Score how well a finding is grounded by external reference MCPs.

        Scans the case audit directory for evidence of declared reference MCP
        usage. Returns WEAK/PARTIAL/STRONG with suggestions for unconsulted
        sources.

        Returns empty dict when STRONG (2+ sources consulted).
        """
        case_dir = self.active_case_dir
        if case_dir is None or not case_dir.exists():
            return {}

        available = _declared_reference_backends()
        if not available:
            return self._grounding_result([], finding)

        # A reference backend counts as consulted when EITHER:
        #  (1) the finding cites an audit_id produced by that backend, or
        #  (2) the backend left a non-empty per-case audit JSONL.
        # Crediting cited audit_ids is essential in DB-active mode, where the
        # transport audit is written to Postgres and the local JSONL may be
        # absent/empty even though kb_search_knowledge actually ran — the prior
        # JSONL-only check made every finding read "WEAK / forensic-rag missing"
        # after real KB searches, training the agent to ignore the signal.
        cited_aids: list[str] = [
            str(aid)
            for aid in (finding.get("audit_ids") or [])
            if isinstance(aid, str) and aid
        ]
        cited_prefixes = {
            aid.split("-", 1)[0].lower()
            for aid in cited_aids
            if "-" in aid and not _UUID_PATTERN.match(aid)
        }
        # For gateway canonical UUIDs (envelope_event_id), resolve the backend name
        # from DB so the grounding scorer can credit the correct add-on plane.
        uuid_cited_backends: set[str] = set()
        uuid_aids = [aid for aid in cited_aids if _UUID_PATTERN.match(aid)]
        if uuid_aids:
            try:
                from sift_core.active_case_context import db_authority_active
                from sift_core.investigation_store import control_plane_dsn

                if db_authority_active():
                    dsn = control_plane_dsn()
                    if dsn:
                        import psycopg

                        db_case_id = self._db_case_id()
                        with psycopg.connect(dsn) as _conn:
                            with _conn.cursor() as _cur:
                                if db_case_id:
                                    _cur.execute(
                                        "select details->>'backend' from app.audit_events"
                                        " where case_id = %s"
                                        " and details->>'envelope_event_id' = any(%s)"
                                        " limit %s",
                                        (db_case_id, uuid_aids, len(uuid_aids) + 1),
                                    )
                                else:
                                    _cur.execute(
                                        "select details->>'backend' from app.audit_events"
                                        " where details->>'envelope_event_id' = any(%s)"
                                        " limit %s",
                                        (uuid_aids, len(uuid_aids) + 1),
                                    )
                                for row in _cur.fetchall():
                                    bk = row[0]
                                    if bk:
                                        uuid_cited_backends.add(bk.lower())
            except Exception:
                pass  # DB not reachable — fall through to JSONL check

        consulted: list[str] = []
        for mcp_name in available:
            # Mirror AuditWriter's prefix derivation: strip "-mcp" and dashes.
            prefix = mcp_name.replace("-mcp", "").replace("-", "").lower()
            # Credit via scheme-format audit_id prefix match.
            if prefix and prefix in cited_prefixes:
                consulted.append(mcp_name)
                continue
            # Credit via DB-resolved envelope_event_id → backend name.
            if mcp_name.lower() in uuid_cited_backends:
                consulted.append(mcp_name)
                continue
            for audit_dir in self._candidate_audit_dirs(case_dir):
                audit_file = audit_dir / f"{mcp_name}.jsonl"
                if audit_file.exists() and audit_file.stat().st_size > 0:
                    consulted.append(mcp_name)
                    break

        return self._grounding_result(consulted, finding, available)

    def _grounding_result(
        self,
        consulted: list[str],
        finding: dict,
        available: list[str] | None = None,
    ) -> dict:
        """Build grounding score result from consulted sources list."""
        if len(consulted) >= 2:
            return {}  # STRONG — don't clutter

        # Only flag backends that are actually deployed (have audit files)
        check_set = available if available is not None else _declared_reference_backends()
        missing = [m for m in check_set if m not in consulted]
        # No deployed grounding backends — nothing to flag
        if not consulted and not missing:
            return {}
        # If finding has provenance chain to registered evidence, at least PARTIAL
        has_provenance = bool(finding.get("source_evidence"))
        level = "PARTIAL" if consulted or has_provenance else "WEAK"

        # Load corroboration suggestions from FK for unconsulted sources
        suggestions = []
        finding_type = finding.get("type", "")
        if finding_type:
            try:
                from forensic_knowledge import loader

                checks = loader.get_corroboration(finding_type)
                if checks:
                    for check in checks:
                        check_text = check.get("check", "")
                        # Only suggest checks from missing MCPs
                        for mcp in missing:
                            short_name = mcp.replace("-mcp", "")
                            if short_name in check_text.lower():
                                reason = check.get("reason", "")
                                suggestions.append(
                                    f"{check_text} — {reason}" if reason else check_text
                                )
            except Exception:
                pass  # FK not available — skip suggestions

        result: dict[str, Any] = {
            "level": level,
            "sources_consulted": consulted,
            "sources_missing": missing,
        }
        if suggestions:
            result["suggestions"] = suggestions

        return result

    # --- Provenance Classification ---

    # Provenance tier priority: MCP > HOOK > SHELL
    _PROVENANCE_TIERS = ("MCP", "HOOK", "SHELL")

    def _classify_provenance(self, audit_ids: list[str], case_dir: Path) -> dict:
        """Classify audit IDs by provenance tier.

        Scans audit/*.jsonl to determine where each audit_id came from:
        - MCP: found in any audit file except claude-code.jsonl
        - HOOK: found in claude-code.jsonl
        - NONE: not found in any audit file or malformed ID

        Evidence IDs must match the format: prefix-examiner-YYYYMMDD-NNN.
        Malformed IDs (path traversal, unicode, injection) are classified as NONE.

        Returns {"summary": tier, "mcp": [...], "hook": [...], "shell": [...], "none": [...]}.
        """
        # Build audit_id -> source lookup from every plausible audit dir for the
        # case (AUT2-B3: the gateway/worker/CLI can write to different dirs).
        eid_source: dict[str, str] = {}
        for audit_dir in self._candidate_audit_dirs(case_dir):
            if not audit_dir.is_dir():
                continue
            for jsonl_file in audit_dir.glob("*.jsonl"):
                source = "HOOK" if jsonl_file.name == "claude-code.jsonl" else "MCP"
                try:
                    with open(jsonl_file, encoding="utf-8") as f:
                        for line in f:
                            line = line.strip()
                            if not line:
                                continue
                            try:
                                entry = json.loads(line)
                                eid = entry.get("audit_id", "")
                                if not eid:
                                    continue
                                existing = eid_source.get(eid)
                                if existing is None:
                                    eid_source[eid] = source
                                elif source == "MCP":
                                    # MCP > HOOK priority
                                    eid_source[eid] = "MCP"
                            except json.JSONDecodeError:
                                continue
                except OSError:
                    continue

        # Classify each audit_id
        result: dict[str, list[str]] = {
            "mcp": [],
            "hook": [],
            "shell": [],
            "none": [],
        }
        for eid in audit_ids:
            # Reject malformed audit IDs (path traversal, homoglyphs, injection).
            # Accept scheme-format ids (prefix-examiner-YYYYMMDD-NNN) AND gateway
            # canonical UUIDs (envelope_event_id assigned by AuditEnvelopeMiddleware).
            if not (_AUDIT_ID_PATTERN.match(eid) or _UUID_PATTERN.match(eid)):
                result["none"].append(eid)
                continue
            source = None
            for candidate in self._audit_id_candidates(eid):
                source = eid_source.get(candidate)
                if source:
                    break
            if not source and self._db_audit_id_known(eid):
                # Recorded by the gateway DB transport audit (app.audit_events)
                # even though the local JSONL mirror has not caught up.
                source = "MCP"
            if source:
                result[source.lower()].append(eid)
            else:
                result["none"].append(eid)

        # Compute summary tier
        tiers_present = set()
        if result["mcp"]:
            tiers_present.add("MCP")
        if result["hook"]:
            tiers_present.add("HOOK")
        if result["shell"]:
            tiers_present.add("SHELL")
        has_none = bool(result["none"])

        if not tiers_present:
            summary = "NONE"
        elif len(tiers_present) == 1 and not has_none:
            summary = next(iter(tiers_present))
        else:
            # Mixed tiers or any NONE with other tiers
            summary = "MIXED"

        result["summary"] = summary  # type: ignore[assignment]
        return result

    # --- Internal helpers ---

    def _resolve_case_dir(self, case_id: str | None) -> Path:
        if case_id:
            _validate_case_id(case_id)
            d = self.cases_dir / case_id
            if not d.exists():
                raise ValueError(f"Case not found: {case_id}")
            return d
        return self._require_active_case()

    def _load_case_meta(self, case_dir: Path) -> dict:
        try:
            with open(case_dir / "CASE.yaml") as f:
                return yaml.safe_load(f) or {}
        except (yaml.YAMLError, OSError) as e:
            logger.warning("Failed to load CASE.yaml from %s: %s", case_dir, e)
            return {}

    # --- Data I/O (case root) ---

    def _load_db_investigation(self, method: str) -> list[dict] | None:
        """Read findings/timeline/iocs/todos from DB authority in DB-active mode.

        Returns None in legacy/file mode so callers fall back to the JSON file.
        This is the chokepoint that makes file tampering inert in DB-active mode:
        every authoritative read (agent list tools, IOC dedup, id sequencing,
        report inputs) resolves through the DB store, not the case JSON.
        """
        case_id = self._db_case_id()
        if not case_id:
            return None
        store = self._investigation_store()
        if store is None:
            from sift_core.investigation_store import InvestigationStoreError

            raise InvestigationStoreError(
                "DB authority is active but the investigation store is unavailable; "
                "refusing to read investigation state from files."
            )
        rows = getattr(store, method)(case_id)
        return rows if isinstance(rows, list) else []

    def _load_findings(self, case_dir: Path) -> list[dict]:
        db = self._load_db_investigation("list_findings")
        if db is not None:
            return db
        return self._load_json_file(case_dir / "findings.json", [])

    def _save_findings(self, case_dir: Path, findings: list[dict]) -> None:
        _protected_write(
            case_dir / "findings.json", json.dumps(findings, indent=2, default=str)
        )

    def _load_timeline(self, case_dir: Path) -> list[dict]:
        db = self._load_db_investigation("list_timeline")
        if db is not None:
            return db
        return self._load_json_file(case_dir / "timeline.json", [])

    def _save_timeline(self, case_dir: Path, timeline: list[dict]) -> None:
        _protected_write(
            case_dir / "timeline.json", json.dumps(timeline, indent=2, default=str)
        )

    def _load_iocs(self, case_dir: Path) -> list[dict]:
        db = self._load_db_investigation("list_iocs")
        if db is not None:
            return db
        return self._load_json_file(case_dir / "iocs.json", [])

    def _save_iocs(self, case_dir: Path, iocs: list[dict]) -> None:
        _protected_write(
            case_dir / "iocs.json", json.dumps(iocs, indent=2, default=str)
        )

    def _process_iocs(self, finding: dict, case_dir: Path) -> int:
        """Extract IOCs from finding, create/update IOC records. Returns count."""
        raw_iocs = finding.get("iocs", [])
        if not raw_iocs:
            return 0
        # Flatten dict format: {"IPv4": ["10.0.1.5"]} → ["10.0.1.5"]
        if isinstance(raw_iocs, dict):
            raw_iocs = [
                v
                for vals in raw_iocs.values()
                for v in (vals if isinstance(vals, list) else [vals])
            ]
        if not isinstance(raw_iocs, list):
            return 0

        host = finding.get("host", "")
        finding_id = finding.get("id", "")
        examiner = finding.get("examiner", "")
        confidence = finding.get("confidence", "")
        mitre_ids = finding.get("mitre_ids", [])
        now = datetime.now(timezone.utc).isoformat()

        iocs = self._load_iocs(case_dir)
        ioc_by_value = {_normalize_ioc(ioc["value"]): ioc for ioc in iocs}
        touched_iocs: list[dict] = []

        # Contextual hints for ambiguous IOC classification
        affected_account = finding.get("affected_account", "")
        account_names = set()
        if affected_account:
            account_names.add(affected_account.lower().strip())
            # Also add bare username if domain\user format
            if "\\" in affected_account:
                account_names.add(affected_account.split("\\", 1)[1].lower().strip())

        for raw in raw_iocs[:100]:
            # Support explicit type: {"value": "rsydow-a", "type": "user-account"}
            if isinstance(raw, dict) and "value" in raw:
                value = _refang_ioc(str(raw["value"]).strip())
                explicit_type = raw.get("type", "")
            else:
                value = _refang_ioc(str(raw).strip())
                explicit_type = ""
            if not value:
                continue
            # Strip port from IPv4 before dedup (10.0.0.1:8443 → 10.0.0.1)
            if explicit_type:
                ioc_type = explicit_type
                category = "identity" if "account" in explicit_type else "host"
            else:
                ioc_type, category = _detect_ioc_type(value)
                # Override unknown → user-account if value matches affected_account
                if ioc_type == "unknown" and value.lower() in account_names:
                    ioc_type, category = "user-account", "identity"
            if ioc_type == "ipv4-addr" and re.search(r":\d{1,5}$", value):
                value = re.sub(r":\d{1,5}$", "", value)
            dedup_key = _normalize_ioc(value)

            if dedup_key in ioc_by_value:
                existing = ioc_by_value[dedup_key]
                if finding_id not in existing.get("source_findings", []):
                    existing.setdefault("source_findings", []).append(finding_id)
                sighting = {"host": host, "finding_id": finding_id}
                if sighting not in existing.get("sightings", []):
                    existing.setdefault("sightings", []).append(sighting)
                if _conf_rank(confidence) < _conf_rank(existing.get("confidence", "")):
                    existing["confidence"] = confidence
                for mid in mitre_ids or []:
                    if mid not in existing.get("mitre_techniques", []):
                        existing.setdefault("mitre_techniques", []).append(mid)
                existing["modified_at"] = now
                existing["content_hash"] = _compute_ioc_hash(existing)
                touched_iocs.append(existing)
            else:
                seq = _next_seq(iocs, "id", "IOC", examiner)
                new_ioc = {
                    "id": f"IOC-{examiner}-{seq:03d}",
                    "value": value,
                    "type": ioc_type,
                    "category": category,
                    "description": "",
                    "status": "DRAFT",
                    "confidence": confidence,
                    "source_findings": [finding_id],
                    "sightings": [{"host": host, "finding_id": finding_id}]
                    if host
                    else [{"host": "", "finding_id": finding_id}],
                    "mitre_techniques": list(mitre_ids) if mitre_ids else [],
                    "tags": [],
                    "manually_reviewed": False,
                    "examiner": examiner,
                    "created_at": now,
                    "modified_at": now,
                }
                new_ioc["content_hash"] = _compute_ioc_hash(new_ioc)
                iocs.append(new_ioc)
                ioc_by_value[dedup_key] = new_ioc
                touched_iocs.append(new_ioc)

        # K2: persist touched IOC rows to DB authority first (fails closed in
        # DB-active mode). IOC file remains a mirror/export.
        for ioc in touched_iocs:
            self._persist_investigation("ioc", ioc["id"], ioc)
        self._save_iocs(case_dir, iocs)
        return len(raw_iocs)

    def _load_todos(self, case_dir: Path) -> list[dict]:
        db = self._load_db_investigation("list_todos")
        if db is not None:
            return db
        return self._load_json_file(case_dir / "todos.json", [])

    def _save_todos(self, case_dir: Path, todos: list[dict]) -> None:
        _atomic_write(case_dir / "todos.json", json.dumps(todos, indent=2, default=str))

    def _load_evidence_registry(self, case_dir: Path) -> dict:
        return self._load_json_file(case_dir / "evidence.json", {"files": []})

    # --- Generic helpers ---

    def _load_json_file(self, path: Path, default: Any) -> Any:
        """Load a JSON file, returning default on missing or corrupt.

        If the file exists and has content but fails to parse, raises
        ValueError to prevent silent data loss on the next write.
        """
        if not path.exists():
            return default
        try:
            data = path.read_text()
        except OSError as e:
            logger.error("Failed to read JSON file %s: %s", path, e)
            raise ValueError(f"Cannot read {path.name}: {e}") from e
        if not data.strip():
            return default
        try:
            return json.loads(data)
        except json.JSONDecodeError as e:
            logger.error("Corrupt JSON file: %s", path)
            raise ValueError(
                f"{path.name} is corrupt (invalid JSON). "
                f"Refusing to overwrite — fix or restore from backup."
            ) from e
