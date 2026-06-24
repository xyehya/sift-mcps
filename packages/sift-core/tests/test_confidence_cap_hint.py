"""W3: confidence cap-hint — auto-derive a confidence CEILING from resolved
provenance and clamp the agent-supplied value DOWN to it (never up).

Operator decision (AUDIT_HARDENING_SPEC §W3-DEC = CAP-HINT):
``final = min(agent_confidence, derived_ceiling)`` by ``_CONF_RANKS`` rank order.
Provenance may only LOWER the agent's value. NEW findings only (confidence is
inside the content hash; backfilling would mutate existing hashes). A
``confidence_derivation`` companion field records the reasoning and is EXCLUDED
from the content hash; ``confidence`` itself stays IN the hash.
"""

from __future__ import annotations

import inspect
import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

import sift_core.case_manager as cm
from sift_core.case_io import case_audit_dir, case_records_dir
from sift_core.case_manager import CaseManager, _derive_confidence_ceiling
from sift_core.investigation_store import HASH_EXCLUDE_KEYS, compute_content_hash


# --------------------------------------------------------------------------- #
# Worktree-source proof: assert the code under test is THIS worktree's copy.
# --------------------------------------------------------------------------- #
def test_source_is_this_worktree():
    src = inspect.getfile(_derive_confidence_ceiling)
    assert "portal-v3-p0-foundation" in src, src
    assert src.endswith("sift_core/case_manager.py"), src
    # confidence_derivation is in the hash-exclude set, confidence is NOT.
    assert "confidence_derivation" in HASH_EXCLUDE_KEYS
    assert "confidence" not in HASH_EXCLUDE_KEYS


# --------------------------------------------------------------------------- #
# 1. Pure helper: ceiling mapping across all four tiers (each branch).
# --------------------------------------------------------------------------- #
class TestDeriveCeilingMapping:
    def test_high_full_two_mcp_no_none(self):
        prov = {"mcp": ["a", "b"], "hook": [], "shell": [], "none": []}
        assert _derive_confidence_ceiling(prov, "FULL", "evidence/x", []) == "HIGH"

    def test_not_high_when_full_two_mcp_but_a_none_present(self):
        prov = {"mcp": ["a", "b"], "hook": [], "shell": [], "none": ["bad"]}
        # FULL + 2 MCP but a NONE id present -> drops to MEDIUM (>=1 MCP + FULL).
        assert _derive_confidence_ceiling(prov, "FULL", "ev", []) == "MEDIUM"

    def test_not_high_when_two_mcp_but_partial_grade(self):
        prov = {"mcp": ["a", "b"], "hook": [], "shell": [], "none": []}
        # PARTIAL grade -> not HIGH; 2 resolved + source -> MEDIUM.
        assert _derive_confidence_ceiling(prov, "PARTIAL", "ev", []) == "MEDIUM"

    def test_medium_full_one_mcp(self):
        prov = {"mcp": ["a"], "hook": [], "shell": [], "none": []}
        assert _derive_confidence_ceiling(prov, "FULL", None, []) == "MEDIUM"

    def test_medium_two_resolved_with_source_partial(self):
        prov = {"mcp": ["a"], "hook": ["b"], "shell": [], "none": []}
        assert _derive_confidence_ceiling(prov, "PARTIAL", "ev", []) == "MEDIUM"

    def test_low_two_resolved_without_source_partial(self):
        prov = {"mcp": ["a"], "hook": ["b"], "shell": [], "none": []}
        # 2 resolved but no source_evidence and not FULL -> below MEDIUM -> LOW.
        assert _derive_confidence_ceiling(prov, "PARTIAL", None, []) == "LOW"

    def test_low_single_resolved_partial(self):
        prov = {"mcp": ["a"], "hook": [], "shell": [], "none": []}
        assert _derive_confidence_ceiling(prov, "PARTIAL", None, []) == "LOW"

    def test_low_shell_only_with_validated_commands(self):
        prov = {"mcp": [], "hook": [], "shell": [], "none": []}
        cmds = [{"command": "grep x", "purpose": "p"}]
        assert _derive_confidence_ceiling(prov, "PARTIAL", None, cmds) == "LOW"

    def test_speculative_only_none_ids(self):
        prov = {"mcp": [], "hook": [], "shell": [], "none": ["x", "y"]}
        assert _derive_confidence_ceiling(prov, "PARTIAL", None, []) == "SPECULATIVE"

    def test_speculative_empty_no_commands(self):
        prov = {"mcp": [], "hook": [], "shell": [], "none": []}
        assert _derive_confidence_ceiling(prov, "PARTIAL", None, []) == "SPECULATIVE"


# --------------------------------------------------------------------------- #
# Integration fixtures (file-mode CaseManager, mirrors the artifact-audit test).
# --------------------------------------------------------------------------- #
AUDIT_ID = "siftcore-alice-20260610-001"
AUDIT_ID2 = "siftcore-alice-20260610-002"


def _write_audit_entry(audit_dir: Path, audit_id: str, tool: str = "run_command") -> None:
    audit_dir.mkdir(parents=True, exist_ok=True)
    entry = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "mcp": "sift-core",
        "tool": tool,
        "audit_id": audit_id,
        "examiner": "alice",
    }
    with open(audit_dir / "sift-core.jsonl", "a", encoding="utf-8") as f:
        f.write(json.dumps(entry) + "\n")


def _register_evidence(case_dir: Path) -> None:
    records = case_records_dir(case_dir)
    records.mkdir(parents=True, exist_ok=True)
    (case_dir / "evidence").mkdir(exist_ok=True)
    (case_dir / "evidence" / "auth.log").write_text("log line\n")
    manifest = {
        "files": [
            {"path": "evidence/auth.log", "sha256": "0" * 64, "status": "SEALED"}
        ]
    }
    (records / "evidence-manifest.json").write_text(json.dumps(manifest))


@pytest.fixture
def file_manager(tmp_path, monkeypatch):
    case_dir = tmp_path / "case-w3"
    case_dir.mkdir()
    (case_dir / "CASE.yaml").write_text("case_id: case-w3\nstatus: active\n")
    _register_evidence(case_dir)
    monkeypatch.setenv("SIFT_CASE_DIR", str(case_dir))
    monkeypatch.delenv("SIFT_DB_ACTIVE", raising=False)
    monkeypatch.delenv("SIFT_AUDIT_DIR", raising=False)
    monkeypatch.delenv("SIFT_CONTROL_PLANE_DSN", raising=False)
    return CaseManager(), case_dir


def _shell_finding(confidence: str) -> dict:
    """A shell-only analytical finding (no artifacts). Provenance grade=PARTIAL,
    classify_provenance summary=NONE, but validated_commands present -> ceiling
    LOW. Survives the hard gate via supporting_commands."""
    return {
        "title": "Shell-derived observation",
        "type": "finding",
        "host": "WS01",
        "observation": "obs",
        "interpretation": "interp",
        "confidence": confidence,
        "confidence_justification": "j",
        "event_timestamp": "2026-06-10T00:00:00Z",
    }


SUPPORTING = [
    {"command": "grep root /var/log/auth.log", "purpose": "find root logons",
     "output_excerpt": "Accepted password for root"}
]


# --------------------------------------------------------------------------- #
# 2. Clamp DOWN: agent HIGH on shell-only (ceiling LOW) -> final LOW, clamped,
#    warning emitted, confidence_derivation recorded.
# --------------------------------------------------------------------------- #
class TestClampDown:
    def test_agent_high_shell_only_clamped_to_low(self, file_manager):
        mgr, case_dir = file_manager
        res = mgr.record_finding(
            _shell_finding("HIGH"),
            supporting_commands=SUPPORTING,
            examiner_override="alice",
        )
        assert res["status"] == "STAGED", res
        f = json.loads((case_dir / "findings.json").read_text())[-1]
        assert f["confidence"] == "LOW", f["confidence"]
        cd = f["confidence_derivation"]
        assert cd["agent"] == "HIGH"
        assert cd["derived_ceiling"] == "LOW"
        assert cd["final"] == "LOW"
        assert cd["clamped"] is True
        assert cd["basis"]["prov_grade"] == "PARTIAL"
        # Downgrade surfaced through the existing warnings channel.
        assert "confidence capped HIGH->LOW" in res.get("warning", "")


# --------------------------------------------------------------------------- #
# 3. Humility preserved: agent LOW with strong (FULL/2-MCP) provenance stays LOW
#    (never raised). Use the pure ceiling = HIGH but clamp keeps the weaker LOW.
# --------------------------------------------------------------------------- #
class TestHumilityPreserved:
    def test_agent_low_strong_provenance_stays_low(self, file_manager, monkeypatch):
        mgr, case_dir = file_manager
        # Force a strong ceiling regardless of the achievable grade in this harness.
        monkeypatch.setattr(cm, "_derive_confidence_ceiling", lambda *a, **k: "HIGH")
        res = mgr.record_finding(
            _shell_finding("LOW"),
            supporting_commands=SUPPORTING,
            examiner_override="alice",
        )
        assert res["status"] == "STAGED", res
        f = json.loads((case_dir / "findings.json").read_text())[-1]
        assert f["confidence"] == "LOW"  # NOT raised to HIGH
        cd = f["confidence_derivation"]
        assert cd["agent"] == "LOW"
        assert cd["derived_ceiling"] == "HIGH"
        assert cd["final"] == "LOW"
        assert cd["clamped"] is False
        assert "capped" not in res.get("warning", "")


# --------------------------------------------------------------------------- #
# 4. New-findings-only / hash: confidence is IN the hash (the clamped value is
#    the recorded fact); confidence_derivation is EXCLUDED from the hash.
# --------------------------------------------------------------------------- #
class TestHashSemantics:
    def test_confidence_in_hash_derivation_excluded(self, file_manager):
        mgr, case_dir = file_manager
        res = mgr.record_finding(
            _shell_finding("HIGH"),
            supporting_commands=SUPPORTING,
            examiner_override="alice",
        )
        assert res["status"] == "STAGED", res
        f = json.loads((case_dir / "findings.json").read_text())[-1]
        stored_hash = f["content_hash"]

        # Recompute as-stored -> matches (proves derivation excluded already).
        assert compute_content_hash(f) == stored_hash

        # Removing confidence_derivation does NOT change the hash (excluded).
        without_deriv = {k: v for k, v in f.items() if k != "confidence_derivation"}
        assert compute_content_hash(without_deriv) == stored_hash

        # Mutating confidence_derivation does NOT change the hash (excluded).
        mutated = dict(f)
        mutated["confidence_derivation"] = {"agent": "ZZZ", "final": "ZZZ"}
        assert compute_content_hash(mutated) == stored_hash

        # Changing confidence ITSELF DOES change the hash (included = the fact).
        changed_conf = dict(f)
        changed_conf["confidence"] = "MEDIUM"
        assert compute_content_hash(changed_conf) != stored_hash

        # The persisted confidence is the clamped (final) value.
        assert f["confidence"] == "LOW"
        assert compute_content_hash(f) == stored_hash  # final value is hashed


# --------------------------------------------------------------------------- #
# 5. IOC propagation reflects the CLAMPED confidence (not the agent's HIGH).
# --------------------------------------------------------------------------- #
class TestIocPropagation:
    def test_extracted_ioc_inherits_clamped_confidence(self, file_manager):
        mgr, case_dir = file_manager
        finding = _shell_finding("HIGH")
        finding["observation"] = "Beacon to 203.0.113.45 observed"
        finding["iocs"] = ["203.0.113.45"]
        res = mgr.record_finding(
            finding, supporting_commands=SUPPORTING, examiner_override="alice"
        )
        assert res["status"] == "STAGED", res
        iocs = json.loads((case_dir / "iocs.json").read_text())
        assert iocs, "expected an extracted IOC"
        ioc = next(i for i in iocs if i.get("value") == "203.0.113.45"
                   or i.get("indicator") == "203.0.113.45")
        # Propagated confidence is the clamped LOW, never the self-asserted HIGH.
        assert (ioc.get("confidence") or "").upper() == "LOW", ioc


# --------------------------------------------------------------------------- #
# 6. Examiner delta-edit path is NOT clamped (human reviewer stays authoritative).
# --------------------------------------------------------------------------- #
class TestExaminerEditExempt:
    def test_clamp_lives_only_in_record_finding(self):
        # The cap-hint helper is invoked exclusively from record_finding (the
        # agent path). The examiner delta-edit applies field values verbatim and
        # recomputes the hash without re-deriving a ceiling — confidence is a
        # delta-editable field that the human controls.
        from case_dashboard import routes

        assert "confidence" in routes._DELTA_EDITABLE_FIELDS
        edit_src = inspect.getsource(routes)
        assert "_derive_confidence_ceiling" not in edit_src, (
            "examiner edit path must not invoke the cap-hint clamp"
        )
        rf_src = inspect.getsource(cm.CaseManager.record_finding)
        assert "_derive_confidence_ceiling" in rf_src
