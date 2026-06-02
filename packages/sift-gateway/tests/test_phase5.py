"""Phase 5 — central output cap (trust layer).

Covers ``response_guard.output_cap_bytes`` / ``cap_tool_result`` (cap +
disk-spill-for-all), the redact-then-cap ordering invariant, and the
``gateway.yaml`` ``trust.output_cap_bytes`` → ``SIFT_OUTPUT_CAP`` plumbing.
"""

from __future__ import annotations

import hashlib
import os
from pathlib import Path

import pytest
import yaml

from sift_gateway.config import apply_trust_env, load_config
from sift_gateway.response_guard import (
    OUTPUT_CAP_ENV,
    _DEFAULT_OUTPUT_CAP_BYTES,
    cap_tool_result,
    output_cap_bytes,
    redact_tool_result,
)


# ---------------------------------------------------------------------------
# output_cap_bytes resolver
# ---------------------------------------------------------------------------


def test_output_cap_default(monkeypatch):
    monkeypatch.delenv(OUTPUT_CAP_ENV, raising=False)
    assert output_cap_bytes() == _DEFAULT_OUTPUT_CAP_BYTES


def test_output_cap_env_override(monkeypatch):
    monkeypatch.setenv(OUTPUT_CAP_ENV, "4096")
    assert output_cap_bytes() == 4096


@pytest.mark.parametrize("bad", ["0", "-5", "notanint", ""])
def test_output_cap_invalid_env_falls_back(monkeypatch, bad):
    monkeypatch.setenv(OUTPUT_CAP_ENV, bad)
    assert output_cap_bytes() == _DEFAULT_OUTPUT_CAP_BYTES


# ---------------------------------------------------------------------------
# cap_tool_result
# ---------------------------------------------------------------------------


def test_under_cap_is_unchanged():
    text = "small output"
    capped, meta = cap_tool_result(text, max_bytes=1024)
    assert capped == text
    assert meta is None


def test_over_cap_truncates_and_spills(tmp_path):
    case_dir = tmp_path / "case-1"
    case_dir.mkdir()
    full = "A" * 5000
    capped, meta = cap_tool_result(
        full, max_bytes=1000, case_dir=str(case_dir), tool_name="opensearch_search"
    )

    # The returned text is capped at <= max_bytes of real content + a marker.
    assert "[OUTPUT CAPPED BY GATEWAY" in capped
    assert capped.startswith("A" * 1000)
    assert meta is not None
    assert meta["original_bytes"] == 5000
    assert meta["returned_bytes"] <= 1000
    assert meta["cap_bytes"] == 1000

    # Full output persisted under <case>/agent/tool_outputs/ with matching sha.
    out_file = Path(meta["output_file"])
    assert out_file.is_relative_to(case_dir / "agent" / "tool_outputs")
    persisted = out_file.read_bytes()
    assert persisted == full.encode("utf-8")
    assert meta["sha256"] == hashlib.sha256(full.encode("utf-8")).hexdigest()
    assert "opensearch_search" in out_file.name


def test_over_cap_without_case_dir_still_truncates():
    full = "B" * 3000
    capped, meta = cap_tool_result(full, max_bytes=500, case_dir=None, tool_name="t")
    assert capped.startswith("B" * 500)
    assert "NOT persisted" in capped
    assert meta is not None
    assert "output_file" not in meta
    # sha still computed over the full text for audit.
    assert meta["sha256"] == hashlib.sha256(full.encode("utf-8")).hexdigest()


def test_utf8_safe_truncation_boundary():
    # A multibyte char straddling the boundary must not corrupt the output.
    full = "é" * 2000  # each char = 2 bytes UTF-8
    capped, meta = cap_tool_result(full, max_bytes=1001, case_dir=None, tool_name="t")
    # No replacement/garbage char; preview decodes cleanly.
    preview = capped.split("\n\n[OUTPUT CAPPED")[0]
    assert "�" not in preview
    assert meta["returned_bytes"] <= 1001


# ---------------------------------------------------------------------------
# redact-then-cap ordering invariant (mirrors the gateway choke point)
# ---------------------------------------------------------------------------


def test_redact_then_cap_never_leaks_partial_secret(tmp_path):
    case_dir = tmp_path / "case-2"
    case_dir.mkdir()
    secret = "AKIA" + "Q" * 16  # AWS access key pattern
    # Place the secret right before the cap boundary so a cap-first order would
    # slice it in half. Redact-then-cap must fully neutralize it everywhere.
    text = "X" * 990 + secret + "Y" * 4000

    redacted, _ = redact_tool_result(text)
    capped, meta = cap_tool_result(
        redacted, max_bytes=1000, case_dir=str(case_dir), tool_name="t"
    )

    assert secret not in capped
    assert "AKIA" not in capped
    # The persisted full output is the redacted text — secret never hits disk.
    persisted = Path(meta["output_file"]).read_text()
    assert secret not in persisted
    assert "[REDACTED:AWS Access Key]" in persisted


# ---------------------------------------------------------------------------
# config plumbing: trust.output_cap_bytes -> SIFT_OUTPUT_CAP
# ---------------------------------------------------------------------------


def test_apply_trust_env_sets_cap(monkeypatch):
    monkeypatch.delenv(OUTPUT_CAP_ENV, raising=False)
    apply_trust_env({"trust": {"output_cap_bytes": 8192}})
    assert os.environ[OUTPUT_CAP_ENV] == "8192"


def test_apply_trust_env_absent_leaves_env_untouched(monkeypatch):
    monkeypatch.delenv(OUTPUT_CAP_ENV, raising=False)
    apply_trust_env({})
    assert OUTPUT_CAP_ENV not in os.environ


@pytest.mark.parametrize("bad", [0, -1, "abc"])
def test_apply_trust_env_rejects_invalid(bad):
    with pytest.raises(ValueError):
        apply_trust_env({"trust": {"output_cap_bytes": bad}})


def test_load_config_exports_output_cap(tmp_path, monkeypatch):
    monkeypatch.delenv(OUTPUT_CAP_ENV, raising=False)
    cfg_path = tmp_path / "gateway.yaml"
    cfg_path.write_text(
        yaml.safe_dump(
            {
                "case": {"root": str(tmp_path / "cases"), "dir": ""},
                "execute": {"security": {"denied_binaries": ["echo"]}},
                "trust": {"output_cap_bytes": 16384},
            }
        ),
        encoding="utf-8",
    )
    load_config(str(cfg_path))
    assert os.environ[OUTPUT_CAP_ENV] == "16384"
