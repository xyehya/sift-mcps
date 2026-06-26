"""IOC normalization, detection, and hashing helpers.

These are pure functions extracted from case_manager so they can be
tested and reused independently.  No class state is touched here —
callers pass values in and get values back.

DB-authority note: nothing in this module reads or writes case data.
It operates on raw IOC dicts/strings only; the authority boundary
(DB vs file) is enforced by the callers in CaseManager._process_iocs.
"""

from __future__ import annotations

import hashlib
import json
import re

# Confidence rank map (lower = stronger).
_CONF_RANKS: dict[str, int] = {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "SPECULATIVE": 3}


def _conf_rank(conf: str) -> int:
    return _CONF_RANKS.get(conf.upper() if conf else "", 99)


def _refang_ioc(value: str) -> str:
    """Refang defanged IOC values."""
    v = value.replace("[.]", ".").replace("hxxp", "http")
    v = re.sub(r"\[(\W)\]", r"\1", v)
    return v


def _normalize_ioc(value: str) -> str:
    """Normalize IOC value for dedup comparison."""
    v = value.strip()
    if re.match(r"^[a-fA-F0-9]{32,64}$", v):
        return v.lower()
    if "." in v and not v.replace(".", "").isdigit():
        return v.lower().rstrip(".")
    if "\\" in v:
        return v.lower()
    return v


def _detect_ioc_type(value: str) -> tuple[str, str]:
    """Auto-detect IOC type and category from value pattern."""
    v = value.strip()

    # URL (before domain check)
    if re.match(r"^https?://", v, re.IGNORECASE):
        return "url", "network"

    # Email
    if re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", v):
        return "email-addr", "network"

    # File hashes (most specific first)
    if re.match(r"^[a-fA-F0-9]{64}$", v):
        return "file:hash:sha256", "host"
    if re.match(r"^[a-fA-F0-9]{40}$", v):
        return "file:hash:sha1", "host"
    if re.match(r"^[a-fA-F0-9]{32}$", v):
        return "file:hash:md5", "host"

    # IPv4 (strip CIDR/port for detection, store original)
    stripped = re.sub(r"[:/]\d{1,5}$", "", v)
    if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", stripped):
        octets = stripped.split(".")
        if all(0 <= int(o) <= 255 for o in octets):
            return "ipv4-addr", "network"

    # IPv6
    if re.match(r"^[0-9a-fA-F:]{6,}$", v) and v.count(":") >= 2:
        return "ipv6-addr", "network"

    # Registry key
    if re.match(r"^HK(EY_|LM|CU|CR|U\\)", v, re.IGNORECASE):
        return "registry-key", "system"

    # Scheduled task
    if v.startswith("\\Microsoft\\") or v.startswith("\\Windows\\"):
        return "scheduled-task", "system"

    # User account (domain\user or UPN)
    if re.match(r"^[a-zA-Z0-9._-]+\\[a-zA-Z0-9._-]+$", v):
        return "user-account", "identity"

    # File name with executable extension (before domain — .exe/.sys/.dll match domain regex)
    _EXE_EXTS = (
        ".exe",
        ".sys",
        ".dll",
        ".bat",
        ".ps1",
        ".cmd",
        ".vbs",
        ".js",
        ".msi",
        ".scr",
    )
    if "." in v and v.lower().endswith(_EXE_EXTS) and "/" not in v and "\\" not in v:
        return "file:name", "host"

    # Domain name
    if re.match(r"^[a-zA-Z0-9]([a-zA-Z0-9-]*\.)+[a-zA-Z]{2,}$", v):
        return "domain-name", "network"

    # Process command line
    if ".exe " in v.lower() or ".exe\t" in v.lower():
        return "process:command-line", "system"

    # File path
    if "/" in v or "\\" in v:
        return "file:path", "host"

    # File name (has extension)
    if re.match(r"^[^/\\]+\.[a-zA-Z0-9]{1,10}$", v):
        return "file:name", "host"

    # Service name (strict: alphanumeric, 3-30 chars)
    if re.match(r"^[a-zA-Z][a-zA-Z0-9]{2,29}$", v) and (
        v.lower().endswith("svc") or v.lower().endswith("service")
    ):
        return "service-name", "system"

    return "unknown", "unknown"


def _compute_ioc_hash(ioc: dict) -> str:
    """Compute content hash for IOC using whitelist of stable fields."""
    hashable = {
        k: ioc.get(k)
        for k in (
            "value",
            "type",
            "category",
            "description",
            "tags",
            "mitre_techniques",
        )
        if ioc.get(k) is not None
    }
    canonical = json.dumps(hashable, sort_keys=True, default=str)
    return hashlib.sha256(canonical.encode()).hexdigest()
