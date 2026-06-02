"""Gateway response secret scanner and redactor (Liquefy Approach C).

Patterns ported from liquefy/tools/liquefy_leakhunter.py SECRET_PATTERNS.
Do NOT import Liquefy — patterns are embedded here.

Default behaviour:
  critical + high severity matches → redacted inline as [REDACTED:{pattern_name}]
  medium severity matches          → flagged in findings, text unchanged
  override_active=True             → no redaction; findings still returned for audit
"""

from __future__ import annotations

import hashlib
import logging
import os
import re
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class _Pattern:
    name: str
    regex: re.Pattern
    severity: str  # "critical" | "high" | "medium"


_PATTERNS: list[_Pattern] = [
    # ── critical ──────────────────────────────────────────────────────────────
    _Pattern("AWS Access Key",    re.compile(r'AKIA[0-9A-Z]{16}'), "critical"),
    _Pattern("AWS Secret Key",    re.compile(r'(?i)aws[_\-]?secret[_\-]?access[_\-]?key\s*[=:]\s*[A-Za-z0-9/+=]{40}'), "critical"),
    _Pattern("GitHub Token",      re.compile(r'gh[pousr]_[A-Za-z0-9_]{36,}'), "critical"),
    _Pattern("GitHub Classic PAT",re.compile(r'github_pat_[A-Za-z0-9_]{82,}'), "critical"),
    _Pattern("OpenAI API Key",    re.compile(r'sk-[A-Za-z0-9]{20,}T3BlbkFJ[A-Za-z0-9]{20,}'), "critical"),
    _Pattern("Anthropic Key",     re.compile(r'sk-ant-[A-Za-z0-9\-]{80,}'), "critical"),
    _Pattern("Stripe Key",        re.compile(r'(?:sk|pk)_(?:test|live)_[A-Za-z0-9]{24,}'), "critical"),
    _Pattern("Discord Token",     re.compile(r'[MN][A-Za-z\d]{23,}\.[\w-]{6}\.[\w-]{27,}'), "critical"),
    _Pattern("RSA Private Key",   re.compile(r'-----BEGIN (?:RSA )?PRIVATE KEY-----'), "critical"),
    _Pattern("EC Private Key",    re.compile(r'-----BEGIN EC PRIVATE KEY-----'), "critical"),
    _Pattern("OpenSSH Private Key", re.compile(r'-----BEGIN OPENSSH PRIVATE KEY-----'), "critical"),
    _Pattern("Connection String", re.compile(r'(?:mongodb|postgres|mysql|redis|amqp)://[^\s"\']+@[^\s"\']+'), "critical"),
    _Pattern("API Key Config",    re.compile(r'(?i)(?:api_key|secret_key|master_secret)\s*[=:]\s*["\']?[^\s"\']{12,}'), "critical"),
    _Pattern("Mnemonic Seed",     re.compile(r'(?i)(?:mnemonic|seed\s*phrase)\s*[=:]\s*"[a-z\s]{20,}"'), "critical"),
    _Pattern("Hex Private Key",   re.compile(r'(?i)private[_\-]?key\s*[=:]\s*["\']?(?:0x)?[0-9a-fA-F]{64}'), "critical"),
    # ── high ──────────────────────────────────────────────────────────────────
    _Pattern("Slack Token",       re.compile(r'xox[bpras]-[A-Za-z0-9\-]{10,}'), "high"),
    _Pattern("Google API Key",    re.compile(r'AIza[0-9A-Za-z\-_]{35}'), "high"),
    _Pattern("Telegram Bot Token",re.compile(r'\d{8,10}:[A-Za-z0-9_-]{35}'), "high"),
    _Pattern("Generic Password",  re.compile(r'(?i)(?:password|passwd|pwd)\s*[=:]\s*["\']?[^\s"\']{8,}'), "high"),
    _Pattern("Bearer Token",      re.compile(r'(?i)bearer\s+[A-Za-z0-9\-._~+/]+=*'), "high"),
    _Pattern("JWT Token",         re.compile(r'eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}'), "high"),
    _Pattern("Session Auth Blob", re.compile(r'"auth(?:_token|orization)?"\s*:\s*"[A-Za-z0-9+/=]{20,}"'), "high"),
    # ── medium — flagged, never redacted ──────────────────────────────────────
    _Pattern("Env File Content",  re.compile(r'^[A-Z_]{3,50}=[^\s]{8,}$', re.MULTILINE), "medium"),
    _Pattern("SkillsSnapshot",    re.compile(r'"skillsSnapshot"\s*:\s*\{'), "medium"),
]

_REDACT_SEVERITIES: frozenset[str] = frozenset({"critical", "high"})


# ---------------------------------------------------------------------------
# In-memory override state (per-process — gateway restart resets it)
# ---------------------------------------------------------------------------

_override_state: dict[str, dict] = {}


def enable_override(case_dir_str: str, examiner: str, ttl: int = 600) -> dict:
    """Enable redaction override for ttl seconds. Returns current status."""
    _override_state[case_dir_str] = {
        "expires_at": time.monotonic() + ttl,
        "enabled_by": examiner,
        "ttl": ttl,
    }
    return get_override_status(case_dir_str)


def cancel_override(case_dir_str: str) -> None:
    """Cancel an active override immediately."""
    _override_state.pop(case_dir_str, None)


def is_override_active(case_dir_str: str) -> bool:
    state = _override_state.get(case_dir_str)
    if not state:
        return False
    if time.monotonic() >= state["expires_at"]:
        _override_state.pop(case_dir_str, None)
        return False
    return True


def get_override_status(case_dir_str: str) -> dict:
    state = _override_state.get(case_dir_str)
    if not state:
        return {"active": False, "seconds_remaining": 0, "enabled_by": None}
    remaining = state["expires_at"] - time.monotonic()
    if remaining <= 0:
        _override_state.pop(case_dir_str, None)
        return {"active": False, "seconds_remaining": 0, "enabled_by": None}
    return {
        "active": True,
        "seconds_remaining": int(remaining),
        "enabled_by": state["enabled_by"],
    }


# ---------------------------------------------------------------------------
# Scan and redact
# ---------------------------------------------------------------------------


def scan_tool_result(text: str) -> list[dict]:
    """Scan text for all secret patterns.

    Returns list of {pattern_name, severity, char_offset} sorted by offset.
    """
    findings: list[dict] = []
    for pat in _PATTERNS:
        for m in pat.regex.finditer(text):
            findings.append({
                "pattern_name": pat.name,
                "severity": pat.severity,
                "char_offset": m.start(),
            })
    findings.sort(key=lambda f: f["char_offset"])
    return findings


def redact_tool_result(text: str, *, override_active: bool = False) -> tuple[str, list[dict]]:
    """Scan text and redact critical+high secrets unless override is active.

    Returns (redacted_text, findings).
    - findings: all matches from the ORIGINAL text (used for audit — never logged verbatim)
    - medium severity patterns appear in findings but are never redacted
    - override_active=True: text returned unchanged; findings still populated for audit
    """
    findings = scan_tool_result(text)
    if not findings or override_active:
        return text, findings

    redacted = text
    for pat in _PATTERNS:
        if pat.severity in _REDACT_SEVERITIES:
            redacted = pat.regex.sub(f"[REDACTED:{pat.name}]", redacted)
    return redacted, findings


# ---------------------------------------------------------------------------
# Central output cap (trust layer) — the single ceiling on bytes any one tool
# response may deliver to the agent. Applied at the gateway choke point AFTER
# redaction (redact-then-cap, so a secret can never straddle the truncation
# boundary and leak half). Oversized responses are truncated and the full
# (already-redacted) output is spilled to <case>/agent/tool_outputs/ with a
# pointer + sha256. This is a backstop ceiling: run_command keeps its own
# tighter response budget + disk-spill independently.
# ---------------------------------------------------------------------------

OUTPUT_CAP_ENV = "SIFT_OUTPUT_CAP"
_DEFAULT_OUTPUT_CAP_BYTES = 262_144  # 256 KiB
_TOOL_OUTPUT_SUBDIR = ("agent", "tool_outputs")


def output_cap_bytes() -> int:
    """Resolve the central output cap (bytes) from the env, with a safe default.

    The gateway config loader translates ``trust.output_cap_bytes`` in
    ``gateway.yaml`` into ``SIFT_OUTPUT_CAP``; this is the single read path.
    """
    raw = os.environ.get(OUTPUT_CAP_ENV)
    if raw:
        try:
            val = int(raw)
            if val > 0:
                return val
        except ValueError:
            pass
    return _DEFAULT_OUTPUT_CAP_BYTES


def _spill_full_output(text: str, case_dir: str, tool_name: str) -> tuple[str | None, str]:
    """Persist the full (already-redacted) text under <case>/agent/tool_outputs/.

    Returns ``(output_file_or_None, sha256)``. On any write failure the cap
    still applies — we return ``None`` for the path and degrade to a pure
    truncation, never an oversized response.
    """
    data = text.encode("utf-8", errors="replace")
    sha = hashlib.sha256(data).hexdigest()
    try:
        case_resolved = Path(case_dir).resolve()
        out_dir = case_resolved.joinpath(*_TOOL_OUTPUT_SUBDIR)
        # Safety: the target must stay under <case>/agent (parallels run_command).
        if not out_dir.is_relative_to(case_resolved / "agent"):
            logger.warning("output cap: refusing to spill outside case agent dir: %s", out_dir)
            return None, sha
        out_dir.mkdir(parents=True, exist_ok=True)
        ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S_%f")
        safe = "".join(c if c.isalnum() or c in "-_" else "_" for c in tool_name)[:40] or "tool"
        path = out_dir / f"{ts}_{safe}.txt"
        with open(path, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        return str(path), sha
    except OSError as exc:
        logger.warning("output cap: failed to persist full output for %s: %s", tool_name, exc)
        return None, sha


def cap_tool_result(
    text: str,
    *,
    max_bytes: int,
    case_dir: str | None = None,
    tool_name: str = "tool",
) -> tuple[str, dict | None]:
    """Cap an oversized (already-redacted) tool result at ``max_bytes``.

    If ``text`` fits, returns ``(text, None)`` unchanged. Otherwise the full
    text is spilled to disk (when a case dir is available), the text is
    truncated on a UTF-8-safe boundary, a clear marker is appended pointing at
    the persisted file, and a metadata dict is returned for audit + the
    ``_sift_context`` note.
    """
    data = text.encode("utf-8")
    original_bytes = len(data)
    if original_bytes <= max_bytes:
        return text, None

    output_file: str | None = None
    if case_dir:
        output_file, sha = _spill_full_output(text, case_dir, tool_name)
    else:
        sha = hashlib.sha256(data).hexdigest()

    # Truncate on a UTF-8-safe boundary (ignore a split trailing multibyte char).
    truncated = data[:max_bytes].decode("utf-8", errors="ignore")
    returned_bytes = len(truncated.encode("utf-8"))

    pointer = (
        f"full output persisted at {output_file}"
        if output_file
        else "full output NOT persisted (no active case directory)"
    )
    marker = (
        f"\n\n[OUTPUT CAPPED BY GATEWAY: returned {returned_bytes} of {original_bytes} bytes "
        f"(cap {max_bytes}). {pointer}; sha256={sha}. "
        f"Narrow the query or read the persisted file to see the rest.]"
    )

    meta: dict = {
        "tool": tool_name,
        "original_bytes": original_bytes,
        "returned_bytes": returned_bytes,
        "cap_bytes": max_bytes,
        "sha256": sha,
    }
    if output_file:
        meta["output_file"] = output_file
    return truncated + marker, meta
