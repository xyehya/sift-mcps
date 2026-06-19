"""Characterization tests for the IOC helper functions in case_manager.py.

These pin the exact behaviour of the pure IOC helpers before they are
extracted into sift_core/ioc_helpers.py (Refs XYE-74 / D6).  The tests
import directly from the extraction target so they stay valid after the move
with zero changes.
"""

from __future__ import annotations

import importlib

import pytest


# ---------------------------------------------------------------------------
# Helper: resolve from the future extraction path first, fall back to
# case_manager while the code still lives there.  Once the extraction is
# done only the first path will be hit.
# ---------------------------------------------------------------------------

def _import_helpers():
    """Return the module that contains the IOC helpers, wherever they live."""
    try:
        return importlib.import_module("sift_core.ioc_helpers")
    except ModuleNotFoundError:
        return importlib.import_module("sift_core.case_manager")


@pytest.fixture(scope="module")
def H():
    return _import_helpers()


# --- _conf_rank -----------------------------------------------------------

class TestConfRank:
    def test_high_is_lowest_rank(self, H):
        assert H._conf_rank("HIGH") == 0

    def test_medium(self, H):
        assert H._conf_rank("MEDIUM") == 1

    def test_low(self, H):
        assert H._conf_rank("LOW") == 2

    def test_speculative(self, H):
        assert H._conf_rank("SPECULATIVE") == 3

    def test_unknown_returns_99(self, H):
        assert H._conf_rank("BOGUS") == 99

    def test_case_insensitive(self, H):
        assert H._conf_rank("high") == 0
        assert H._conf_rank("Medium") == 1

    def test_empty_returns_99(self, H):
        assert H._conf_rank("") == 99


# --- _refang_ioc ----------------------------------------------------------

class TestRefangIoc:
    def test_dot_brackets_replaced(self, H):
        assert H._refang_ioc("evil[.]com") == "evil.com"

    def test_hxxp_replaced(self, H):
        assert H._refang_ioc("hxxp://evil.com") == "http://evil.com"

    def test_generic_bracket_char(self, H):
        # [/] → /
        assert H._refang_ioc("example[/]path") == "example/path"

    def test_passthrough_when_clean(self, H):
        assert H._refang_ioc("http://normal.com") == "http://normal.com"


# --- _normalize_ioc -------------------------------------------------------

class TestNormalizeIoc:
    def test_hex_hash_lowercased(self, H):
        h = "ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890"
        assert H._normalize_ioc(h) == h.lower()

    def test_domain_lowercased_trailing_dot_stripped(self, H):
        assert H._normalize_ioc("Evil.Com.") == "evil.com"

    def test_windows_path_lowercased(self, H):
        assert H._normalize_ioc("C:\\Windows\\System32") == "c:\\windows\\system32"

    def test_strips_whitespace(self, H):
        assert H._normalize_ioc("  10.0.0.1  ") == "10.0.0.1"

    def test_plain_value_passthrough(self, H):
        assert H._normalize_ioc("generic") == "generic"


# --- _detect_ioc_type -----------------------------------------------------

class TestDetectIocType:
    def test_url(self, H):
        assert H._detect_ioc_type("https://evil.com/payload") == ("url", "network")

    def test_url_http(self, H):
        assert H._detect_ioc_type("http://bad.example") == ("url", "network")

    def test_email(self, H):
        assert H._detect_ioc_type("attacker@evil.com") == ("email-addr", "network")

    def test_sha256(self, H):
        h = "a" * 64
        assert H._detect_ioc_type(h) == ("file:hash:sha256", "host")

    def test_sha1(self, H):
        h = "b" * 40
        assert H._detect_ioc_type(h) == ("file:hash:sha1", "host")

    def test_md5(self, H):
        h = "c" * 32
        assert H._detect_ioc_type(h) == ("file:hash:md5", "host")

    def test_ipv4(self, H):
        assert H._detect_ioc_type("192.168.1.1") == ("ipv4-addr", "network")

    def test_ipv4_with_port(self, H):
        # Strip port before detection — still ipv4
        assert H._detect_ioc_type("10.0.0.1:443") == ("ipv4-addr", "network")

    def test_ipv4_with_cidr(self, H):
        assert H._detect_ioc_type("10.0.0.0/24") == ("ipv4-addr", "network")

    def test_ipv6(self, H):
        assert H._detect_ioc_type("2001:db8::1") == ("ipv6-addr", "network")

    def test_registry_key(self, H):
        assert H._detect_ioc_type("HKLM\\SOFTWARE\\Run") == ("registry-key", "system")
        assert H._detect_ioc_type("HKEY_LOCAL_MACHINE\\Run") == ("registry-key", "system")

    def test_scheduled_task(self, H):
        assert H._detect_ioc_type("\\Microsoft\\Windows\\Task") == ("scheduled-task", "system")

    def test_domain_user_account(self, H):
        assert H._detect_ioc_type("DOMAIN\\username") == ("user-account", "identity")

    def test_executable_extension(self, H):
        assert H._detect_ioc_type("malware.exe") == ("file:name", "host")
        assert H._detect_ioc_type("evil.dll") == ("file:name", "host")
        assert H._detect_ioc_type("script.ps1") == ("file:name", "host")

    def test_domain_name(self, H):
        assert H._detect_ioc_type("evil.example.com") == ("domain-name", "network")

    def test_process_command_line(self, H):
        assert H._detect_ioc_type("cmd.exe /c whoami") == ("process:command-line", "system")

    def test_unix_file_path(self, H):
        assert H._detect_ioc_type("/etc/passwd") == ("file:path", "host")

    def test_windows_file_path(self, H):
        assert H._detect_ioc_type("C:\\Windows\\temp\\evil.bin") == ("file:path", "host")

    def test_file_with_extension(self, H):
        # readme.txt matches the domain-name regex (alphanum dot alphanum),
        # so the actual returned type is domain-name — characterize that.
        assert H._detect_ioc_type("readme.txt") == ("domain-name", "network")

    def test_file_with_extension_no_domain_ambiguity(self, H):
        # Files with executable extensions are caught BEFORE domain check.
        # A generic non-domain extension that has slashes → file:path.
        assert H._detect_ioc_type("/tmp/readme.txt") == ("file:path", "host")

    def test_service_name(self, H):
        assert H._detect_ioc_type("RdpSvc") == ("service-name", "system")
        assert H._detect_ioc_type("WinService") == ("service-name", "system")

    def test_unknown(self, H):
        assert H._detect_ioc_type("just-a-string") == ("unknown", "unknown")


# --- _compute_ioc_hash ----------------------------------------------------

class TestComputeIocHash:
    def test_deterministic(self, H):
        ioc = {
            "value": "10.0.0.1",
            "type": "ipv4-addr",
            "category": "network",
            "description": "attacker IP",
            "tags": ["c2"],
            "mitre_techniques": ["T1071"],
        }
        h1 = H._compute_ioc_hash(ioc)
        h2 = H._compute_ioc_hash(ioc)
        assert h1 == h2

    def test_different_values_differ(self, H):
        h1 = H._compute_ioc_hash({"value": "10.0.0.1", "type": "ipv4-addr", "category": "network"})
        h2 = H._compute_ioc_hash({"value": "10.0.0.2", "type": "ipv4-addr", "category": "network"})
        assert h1 != h2

    def test_non_stable_fields_ignored(self, H):
        """Fields outside the stable set (e.g. modified_at) don't affect hash."""
        base = {"value": "evil.com", "type": "domain-name", "category": "network"}
        ioc_a = {**base, "modified_at": "2024-01-01"}
        ioc_b = {**base, "modified_at": "2025-12-31"}
        assert H._compute_ioc_hash(ioc_a) == H._compute_ioc_hash(ioc_b)

    def test_none_fields_excluded(self, H):
        """None values are excluded from the hash to keep it stable."""
        h1 = H._compute_ioc_hash({"value": "x", "type": "unknown", "category": "unknown", "tags": None})
        h2 = H._compute_ioc_hash({"value": "x", "type": "unknown", "category": "unknown"})
        assert h1 == h2

    def test_returns_sha256_hex(self, H):
        h = H._compute_ioc_hash({"value": "x", "type": "unknown", "category": "unknown"})
        assert len(h) == 64
        int(h, 16)  # must be valid hex


# --- _CONF_RANKS constant -------------------------------------------------

class TestConfRanksConstant:
    """Regression: ensure the four tiers are present with the expected ranks."""

    def test_all_tiers_present(self, H):
        assert set(H._CONF_RANKS.keys()) == {"HIGH", "MEDIUM", "LOW", "SPECULATIVE"}

    def test_ordering(self, H):
        assert H._CONF_RANKS["HIGH"] < H._CONF_RANKS["MEDIUM"]
        assert H._CONF_RANKS["MEDIUM"] < H._CONF_RANKS["LOW"]
        assert H._CONF_RANKS["LOW"] < H._CONF_RANKS["SPECULATIVE"]
