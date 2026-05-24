"""Gateway response secret scanner and redactor (Liquefy Approach C).

Patterns ported from liquefy/tools/liquefy_leakhunter.py SECRET_PATTERNS.
Do NOT import Liquefy — patterns are embedded here.

Default behaviour:
  critical + high severity matches → redacted inline as [REDACTED:{pattern_name}]
  medium severity matches          → flagged in findings, text unchanged
  override_active=True             → no redaction; findings still returned for audit
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass


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
