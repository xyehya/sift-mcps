"""DB-authority regression tests for ioc_helpers (D6 / XYE-74).

These ensure that the IOC helper functions extracted from case_manager:
1. Still produce correct results (no behavioural change from extraction).
2. Do NOT touch DB or file I/O — they are pure functions.
3. _compute_ioc_hash produces stable, collision-resistant hashes over
   the documented stable-field whitelist only.

The helpers are stateless; DB-authority is enforced by CaseManager._process_iocs
which calls them.  These tests confirm the extraction kept that boundary clean.
"""

from __future__ import annotations

import hashlib
import json

import pytest

from sift_core.ioc_helpers import (
    _CONF_RANKS,
    _compute_ioc_hash,
    _conf_rank,
    _detect_ioc_type,
    _normalize_ioc,
    _refang_ioc,
)


# ---------------------------------------------------------------------------
# _conf_rank
# ---------------------------------------------------------------------------

class TestConfRank:
    def test_high_is_lowest_int(self):
        assert _conf_rank("HIGH") == 0

    def test_medium_less_than_low(self):
        assert _conf_rank("MEDIUM") < _conf_rank("LOW")

    def test_unknown_returns_99(self):
        assert _conf_rank("UNKNOWN_TIER") == 99

    def test_empty_string_returns_99(self):
        assert _conf_rank("") == 99

    def test_case_insensitive(self):
        assert _conf_rank("high") == _conf_rank("HIGH")

    def test_speculative_is_weakest_ranked(self):
        assert _conf_rank("SPECULATIVE") > _conf_rank("LOW")


# ---------------------------------------------------------------------------
# _refang_ioc
# ---------------------------------------------------------------------------

class TestRefangIoc:
    def test_defanged_dot(self):
        assert _refang_ioc("evil[.]com") == "evil.com"

    def test_hxxp_protocol(self):
        assert _refang_ioc("hxxps://evil.com") == "https://evil.com"

    def test_defanged_slash(self):
        # [/] → /
        assert _refang_ioc("path[/]to") == "path/to"

    def test_no_change_for_clean_value(self):
        assert _refang_ioc("10.0.0.1") == "10.0.0.1"


# ---------------------------------------------------------------------------
# _normalize_ioc
# ---------------------------------------------------------------------------

class TestNormalizeIoc:
    def test_hash_lowercased(self):
        h = "A" * 32
        assert _normalize_ioc(h) == h.lower()

    def test_domain_lowercased_and_trailing_dot_stripped(self):
        assert _normalize_ioc("Evil.COM.") == "evil.com"

    def test_windows_path_lowercased(self):
        assert _normalize_ioc("C:\\Windows\\System32") == "c:\\windows\\system32"

    def test_plain_string_unchanged(self):
        val = "just-a-word"
        assert _normalize_ioc(val) == val

    def test_strips_whitespace(self):
        assert _normalize_ioc("  10.0.0.1  ") == "10.0.0.1"


# ---------------------------------------------------------------------------
# _detect_ioc_type
# ---------------------------------------------------------------------------

class TestDetectIocType:
    def test_url(self):
        ioc_type, category = _detect_ioc_type("https://evil.example.com/payload")
        assert ioc_type == "url"
        assert category == "network"

    def test_email(self):
        ioc_type, category = _detect_ioc_type("attacker@evil.com")
        assert ioc_type == "email-addr"
        assert category == "network"

    def test_sha256(self):
        ioc_type, category = _detect_ioc_type("a" * 64)
        assert ioc_type == "file:hash:sha256"
        assert category == "host"

    def test_sha1(self):
        ioc_type, category = _detect_ioc_type("b" * 40)
        assert ioc_type == "file:hash:sha1"
        assert category == "host"

    def test_md5(self):
        ioc_type, category = _detect_ioc_type("c" * 32)
        assert ioc_type == "file:hash:md5"
        assert category == "host"

    def test_ipv4(self):
        ioc_type, category = _detect_ioc_type("203.0.113.7")
        assert ioc_type == "ipv4-addr"
        assert category == "network"

    def test_ipv4_with_port_still_detected(self):
        ioc_type, category = _detect_ioc_type("10.0.0.1:443")
        assert ioc_type == "ipv4-addr"

    def test_registry_key(self):
        ioc_type, category = _detect_ioc_type("HKLM\\Software\\Evil")
        assert ioc_type == "registry-key"
        assert category == "system"

    def test_domain(self):
        ioc_type, category = _detect_ioc_type("evil.example.com")
        assert ioc_type == "domain-name"
        assert category == "network"

    def test_exe_filename(self):
        ioc_type, category = _detect_ioc_type("malware.exe")
        assert ioc_type == "file:name"
        assert category == "host"

    def test_domain_user(self):
        ioc_type, category = _detect_ioc_type("CORP\\rsydow")
        assert ioc_type == "user-account"
        assert category == "identity"

    def test_file_path_unix(self):
        ioc_type, category = _detect_ioc_type("/tmp/evil.sh")
        assert ioc_type == "file:path"
        assert category == "host"

    def test_unknown_falls_through(self):
        ioc_type, category = _detect_ioc_type("just-some-word")
        assert ioc_type == "unknown"
        assert category == "unknown"


# ---------------------------------------------------------------------------
# _compute_ioc_hash — DB-authority regression: the hash must be stable and
# must only cover the documented whitelist so DB-stored hashes don't drift.
# ---------------------------------------------------------------------------

class TestComputeIocHash:
    def test_returns_sha256_hex(self):
        digest = _compute_ioc_hash({"value": "10.0.0.1", "type": "ipv4-addr"})
        assert len(digest) == 64
        int(digest, 16)  # raises ValueError if not hex

    def test_deterministic(self):
        ioc = {"value": "10.0.0.1", "type": "ipv4-addr", "category": "network"}
        assert _compute_ioc_hash(ioc) == _compute_ioc_hash(dict(ioc))

    def test_non_whitelisted_fields_ignored(self):
        base = {"value": "evil.com", "type": "domain-name"}
        with_extra = {**base, "examiner": "alice", "created_at": "2026-01-01", "id": "IOC-001"}
        # Extra fields (examiner, created_at, id) must not change the hash so
        # that DB-stored hashes computed at write time remain valid on re-check.
        assert _compute_ioc_hash(base) == _compute_ioc_hash(with_extra)

    def test_whitelisted_field_change_changes_hash(self):
        a = {"value": "evil.com", "type": "domain-name", "category": "network"}
        b = {**a, "category": "host"}
        assert _compute_ioc_hash(a) != _compute_ioc_hash(b)

    def test_matches_manual_sha256(self):
        ioc = {"value": "10.0.0.1", "type": "ipv4-addr"}
        hashable = {k: ioc[k] for k in ("value", "type") if ioc.get(k) is not None}
        expected = hashlib.sha256(
            json.dumps(hashable, sort_keys=True, default=str).encode()
        ).hexdigest()
        assert _compute_ioc_hash(ioc) == expected

    def test_none_values_excluded_from_hashable(self):
        # Fields present but None must be excluded (mirrors whitelist filter).
        ioc_none = {"value": "evil.com", "type": "domain-name", "category": None}
        ioc_absent = {"value": "evil.com", "type": "domain-name"}
        assert _compute_ioc_hash(ioc_none) == _compute_ioc_hash(ioc_absent)
