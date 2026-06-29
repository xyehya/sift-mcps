"""Two-axis confidence ceiling: clamp the agent-supplied confidence DOWN to a
ceiling derived from the (evidence_engaged, grounding_count) axes — never up.

Rebuild model (plan BE-1/BE-5/BE-6):
  ceiling = HIGH  if evidence_engaged and grounding_count >= 2
            MEDIUM if evidence_engaged and grounding_count >= 1
            LOW    otherwise (floor; SPECULATIVE removed entirely)
  final = min(agent_confidence, ceiling) by _CONF_RANKS rank order.

These tests run in DB-authority mode (the only production mode): the audit trail
(`list_audit_provenance_db`), the sealed registry (`list_sealed_evidence_db`) and
the investigation store are all faked, and assertions are made on the captured
`upsert_finding` payload — NOT a findings.json file (file mode no longer grades).
"""

from __future__ import annotations

import inspect

import pytest
import sift_core.case_manager as cm
from sift_core.case_manager import CaseManager, _derive_confidence_ceiling
from sift_core.investigation_store import HASH_EXCLUDE_KEYS, compute_content_hash
from sift_core.ioc_helpers import _conf_rank, normalize_confidence

CASE_UUID = "11111111-1111-1111-1111-111111111111"
_KB = "forensic-rag-mcp"
_WT = "windows-triage-mcp"
_OCTI = "opencti-mcp"
_REF_BACKENDS = [_KB, _WT, _OCTI]


# --------------------------------------------------------------------------- #
# 1. BE-1: the ONE tunable function — full ceiling truth table + single-source.
# --------------------------------------------------------------------------- #
class TestDeriveCeilingTable:
    @pytest.mark.parametrize(
        "engaged,count,expected",
        [
            (True, 0, "LOW"),
            (True, 1, "MEDIUM"),
            (True, 2, "HIGH"),
            (True, 3, "HIGH"),
            (False, 0, "LOW"),
            (False, 1, "LOW"),
            (False, 2, "LOW"),
            (False, 9, "LOW"),
        ],
    )
    def test_ceiling_truth_table(self, engaged, count, expected):
        assert _derive_confidence_ceiling(engaged, count) == expected

    def test_speculative_never_returned(self):
        for engaged in (True, False):
            for count in range(0, 5):
                assert _derive_confidence_ceiling(engaged, count) in {
                    "HIGH",
                    "MEDIUM",
                    "LOW",
                }

    def test_mapping_lives_only_in_the_helper(self):
        """The (engaged, count) -> tier thresholds live ONLY in the helper; the
        hot path delegates and does not duplicate the table (anti-drift)."""
        body = inspect.getsource(cm._derive_confidence_ceiling)
        assert "grounding_count >= 2" in body
        assert "grounding_count >= 1" in body
        assert '"HIGH"' in body and '"MEDIUM"' in body
        rf = inspect.getsource(cm.CaseManager.record_finding)
        assert "_derive_confidence_ceiling(" in rf, "record_finding must delegate"
        assert "grounding_count >= 2" not in rf, "thresholds must not be inlined"


# --------------------------------------------------------------------------- #
# 1b. BE-4: fail-on-revert guard — the grading path is DB-only (no file reads).
# --------------------------------------------------------------------------- #
class TestNoFileBasedGradingPath:
    """Locks the de-backdooring this rebuild performed. The file-coupled and
    agent-fakeable grading symbols must stay DELETED, and no grading function may
    glob audit JSONL or read the evidence file-manifest. Reverting the rewrite
    (reintroducing any file-based / forgeable vector) fails here — the guard the
    plan's BE-4 mandates. Scoped to the grading functions only; the deferred
    activity-log (``actions.jsonl``) and the out-of-grading ``get_case_status``
    manifest read are intentionally NOT in scope.
    """

    def test_deleted_file_based_symbols_stay_deleted(self):
        # module-level xmount/temp path-walker (the CONF-1-IDX root cause)
        assert not hasattr(cm, "_resolve_source_evidence_static")
        # JSONL-globbing graders + the agent-fakeable DB existence probe
        for meth in (
            "_classify_provenance",
            "_candidate_audit_dirs",
            "_db_audit_event_has_audit_id",
        ):
            assert not hasattr(
                CaseManager, meth
            ), f"CaseManager.{meth} must stay deleted (file-based/forgeable grading)"

    def test_grading_functions_read_no_files(self):
        srcs = "\n".join(
            inspect.getsource(fn)
            for fn in (
                CaseManager.record_finding,
                CaseManager._scan_audit_trail,
                CaseManager._score_grounding,
                CaseManager._grounding_result,
                CaseManager._resolve_evidence_engaged,
                CaseManager._next_shell_seq,
                cm._derive_confidence_ceiling,
            )
        )
        for token in (
            ".glob(",  # no audit/*.jsonl globbing
            ".jsonl",  # no JSONL file paths in the grading path
            "load_manifest",  # no evidence file-manifest read
            "_classify_provenance",
            "_resolve_source_evidence_static",
            "_candidate_audit_dirs",
            "_db_audit_event_has_audit_id",
        ):
            assert (
                token not in srcs
            ), f"file-based grading vestige reintroduced: {token!r}"


# --------------------------------------------------------------------------- #
# Shared DB-mode fixture + helpers.
# --------------------------------------------------------------------------- #
class _CapturingStore:
    """In-memory investigation store; captures persisted finding payloads."""

    def __init__(self):
        self.findings: dict = {}
        self.timeline: dict = {}
        self.iocs: dict = {}
        self.todos: dict = {}
        self.finding_order: list[str] = []

    def upsert_finding(self, case_id, item_id, payload, *, actor=None):
        if item_id not in self.findings:
            self.finding_order.append(item_id)
        self.findings[item_id] = dict(payload)
        return {"applied": True}

    def upsert_timeline_event(self, case_id, item_id, payload, *, actor=None):
        self.timeline[item_id] = dict(payload)
        return {"applied": True}

    def upsert_ioc(self, case_id, item_id, payload, *, actor=None):
        self.iocs[item_id] = dict(payload)
        return {"applied": True}

    def upsert_todo(self, case_id, item_id, payload, *, actor=None):
        self.todos[item_id] = dict(payload)
        return {"applied": True}

    def list_findings(self, case_id):
        return list(self.findings.values())

    def list_timeline(self, case_id):
        return list(self.timeline.values())

    def list_iocs(self, case_id):
        return list(self.iocs.values())

    def list_todos(self, case_id):
        return list(self.todos.values())

    def last_finding(self) -> dict:
        assert self.finding_order, "no finding was persisted"
        return self.findings[self.finding_order[-1]]


def _audit_row(
    audit_id: str,
    *,
    tool: str = "run_command",
    backend: str = "",
    evidence_refs=None,
    aliases=None,
    envelope: str = "",
) -> dict:
    """Shape one list_audit_provenance_db row (gateway-written fields)."""
    return {
        "audit_id": audit_id,
        "tool": tool,
        "backend": backend,
        "evidence_refs": list(evidence_refs or []),
        "audit_aliases": list(aliases or []),
        "envelope_event_id": envelope,
        "input_files": [],
        "result_summary": {},
        "params": {},
        "case_id": CASE_UUID,
    }


def _finding(confidence: str, *, audit_ids=None, **extra) -> dict:
    f = {
        "title": "Observation",
        "type": "finding",
        "host": "WS01",
        "observation": "obs",
        "interpretation": "interp",
        "confidence": confidence,
        "confidence_justification": "justified by cited evidence",
        "event_timestamp": "2026-06-10T00:00:00Z",
        "audit_ids": list(audit_ids or []),
    }
    f.update(extra)
    return f


@pytest.fixture
def db_manager(tmp_path, monkeypatch):
    """CaseManager in DB-authority mode; Postgres never dialled.

    `state["audit"]` / `state["sealed"]` are read live by the faked DB readers so
    a test can stage its trail before calling record_finding.
    """
    from sift_core.active_case_context import AuthorityContext, use_active_case_context

    case_dir = tmp_path / "case-w3-db"
    case_dir.mkdir()
    (case_dir / "CASE.yaml").write_text("case_id: case-w3-db\nstatus: active\n")
    monkeypatch.delenv("SIFT_CASE_DIR", raising=False)
    monkeypatch.delenv("SIFT_AUDIT_DIR", raising=False)
    # No DSN: the shell-seq DB count + shell forward-write fail closed without a
    # real connection (the faked DB readers below don't use the DSN).
    monkeypatch.delenv("SIFT_CONTROL_PLANE_DSN", raising=False)
    monkeypatch.setattr(
        "sift_core.investigation_store.resolve_case_metadata",
        lambda: {"case_id": "case-w3-db", "status": "open"},
    )

    state: dict = {"audit": [], "sealed": []}
    store = _CapturingStore()
    monkeypatch.setattr(cm.CaseManager, "_investigation_store", lambda self: store)
    monkeypatch.setattr(
        "sift_core.investigation_store.list_audit_provenance_db",
        lambda cid: list(state["audit"]),
    )
    monkeypatch.setattr(
        "sift_core.investigation_store.list_sealed_evidence_db",
        lambda cid: list(state["sealed"]),
    )
    monkeypatch.setattr(cm, "_declared_reference_backends", lambda: list(_REF_BACKENDS))

    ctx = AuthorityContext(
        case_id=CASE_UUID,
        case_key="case-w3-db",
        artifact_path=str(case_dir),
        db_active=True,
    )
    with use_active_case_context(ctx):
        yield CaseManager(), store, state


# --------------------------------------------------------------------------- #
# 2. HIGH: run_command (engages evidence) + 2 distinct grounding backends.
# --------------------------------------------------------------------------- #
class TestHighCeiling:
    def test_run_command_plus_two_grounding_high_not_clamped(self, db_manager):
        mgr, store, state = db_manager
        state["audit"] = [
            _audit_row("rc-1", tool="run_command", backend="sift-core",
                       evidence_refs=["ev-uuid-1"]),
            _audit_row("kb-1", tool="kb_search_knowledge", backend=_KB),
            _audit_row("wt-1", tool="wintriage_check_process_tree", backend=_WT),
        ]
        state["sealed"] = [
            {"evidence_id": "ev-uuid-1", "path": "evidence/rocba.E01",
             "sha256": "a" * 64, "status": "sealed"}
        ]
        res = mgr.record_finding(
            _finding("HIGH", audit_ids=["rc-1", "kb-1", "wt-1"]),
            examiner_override="alice",
        )
        assert res["status"] == "STAGED", res
        f = store.last_finding()
        assert f["confidence"] == "HIGH"
        assert f["provenance_grade"] == "REFERENCED"
        assert f["grounding"]["sources_count"] == 2
        cd = f["confidence_derivation"]
        assert cd["basis"]["evidence_engaged"] is True
        assert cd["basis"]["grounding_count"] == 2
        assert cd["derived_ceiling"] == "HIGH"
        assert cd["clamped"] is False
        # source_evidence resolves the run_command's sealed evidence_ref (display).
        assert f.get("source_evidence") == "evidence/rocba.E01"

    def test_opensearch_citation_engages_evidence(self, db_manager):
        """An opensearch_* citation engages Axis A (indices exist only post-ingest)."""
        mgr, store, state = db_manager
        state["audit"] = [
            _audit_row("os-1", tool="opensearch_search", backend="opensearch-mcp"),
            _audit_row("kb-1", tool="kb_search_knowledge", backend=_KB),
            _audit_row("wt-1", tool="wintriage_check_system", backend=_WT),
        ]
        res = mgr.record_finding(
            _finding("HIGH", audit_ids=["os-1", "kb-1", "wt-1"]),
            examiner_override="alice",
        )
        assert res["status"] == "STAGED", res
        f = store.last_finding()
        assert f["provenance_grade"] == "REFERENCED"
        assert f["confidence"] == "HIGH"
        assert f["confidence_derivation"]["basis"]["evidence_engaged"] is True


# --------------------------------------------------------------------------- #
# 3. Clamp DOWN: engaged but grounding 0 -> ceiling LOW; agent HIGH -> LOW.
# --------------------------------------------------------------------------- #
class TestClampDown:
    def test_engaged_zero_grounding_caps_high_to_low(self, db_manager):
        mgr, store, state = db_manager
        state["audit"] = [
            _audit_row("rc-1", tool="run_command", backend="sift-core",
                       evidence_refs=["ev-uuid-1"]),
        ]
        state["sealed"] = [
            {"evidence_id": "ev-uuid-1", "path": "evidence/x.E01",
             "sha256": "a" * 64, "status": "sealed"}
        ]
        res = mgr.record_finding(
            _finding("HIGH", audit_ids=["rc-1"]), examiner_override="alice"
        )
        assert res["status"] == "STAGED", res
        f = store.last_finding()
        assert f["confidence"] == "LOW"
        assert f["provenance_grade"] == "REFERENCED"
        cd = f["confidence_derivation"]
        assert cd["agent"] == "HIGH"
        assert cd["derived_ceiling"] == "LOW"
        assert cd["clamped"] is True
        assert "confidence capped HIGH->LOW" in res.get("warning", "")

    def test_engaged_one_grounding_caps_high_to_medium(self, db_manager):
        mgr, store, state = db_manager
        state["audit"] = [
            _audit_row("rc-1", tool="run_command", backend="sift-core",
                       evidence_refs=["ev-uuid-1"]),
            _audit_row("kb-1", tool="kb_search_knowledge", backend=_KB),
        ]
        state["sealed"] = [
            {"evidence_id": "ev-uuid-1", "path": "evidence/x.E01",
             "sha256": "a" * 64, "status": "sealed"}
        ]
        res = mgr.record_finding(
            _finding("HIGH", audit_ids=["rc-1", "kb-1"]), examiner_override="alice"
        )
        assert res["status"] == "STAGED", res
        f = store.last_finding()
        assert f["confidence"] == "MEDIUM"
        assert f["confidence_derivation"]["derived_ceiling"] == "MEDIUM"
        assert f["grounding"]["sources_count"] == 1

    def test_run_command_without_evidence_refs_not_engaged(self, db_manager):
        """A run_command that did NOT read sealed evidence (no evidence_refs) does
        not engage Axis A — even cited with grounding it floors at LOW."""
        mgr, store, state = db_manager
        state["audit"] = [
            _audit_row("rc-1", tool="run_command", backend="sift-core"),
            _audit_row("kb-1", tool="kb_search_knowledge", backend=_KB),
            _audit_row("wt-1", tool="wintriage_check_system", backend=_WT),
        ]
        res = mgr.record_finding(
            _finding("HIGH", audit_ids=["rc-1", "kb-1", "wt-1"]),
            examiner_override="alice",
        )
        assert res["status"] == "STAGED", res
        f = store.last_finding()
        assert f["provenance_grade"] == "UNREFERENCED"
        assert f["confidence_derivation"]["basis"]["evidence_engaged"] is False
        assert f["confidence"] == "LOW"  # not engaged -> floor


# --------------------------------------------------------------------------- #
# 4. Humility preserved: agent LOW with a HIGH ceiling stays LOW (never raised).
# --------------------------------------------------------------------------- #
class TestHumilityPreserved:
    def test_agent_low_strong_provenance_stays_low(self, db_manager):
        mgr, store, state = db_manager
        state["audit"] = [
            _audit_row("rc-1", tool="run_command", backend="sift-core",
                       evidence_refs=["ev-uuid-1"]),
            _audit_row("kb-1", tool="kb_search_knowledge", backend=_KB),
            _audit_row("wt-1", tool="wintriage_check_system", backend=_WT),
        ]
        state["sealed"] = [
            {"evidence_id": "ev-uuid-1", "path": "evidence/x.E01",
             "sha256": "a" * 64, "status": "sealed"}
        ]
        res = mgr.record_finding(
            _finding("LOW", audit_ids=["rc-1", "kb-1", "wt-1"]),
            examiner_override="alice",
        )
        assert res["status"] == "STAGED", res
        f = store.last_finding()
        assert f["confidence"] == "LOW"  # NOT raised to HIGH
        cd = f["confidence_derivation"]
        assert cd["agent"] == "LOW"
        assert cd["derived_ceiling"] == "HIGH"
        assert cd["clamped"] is False
        assert "capped" not in res.get("warning", "")


# --------------------------------------------------------------------------- #
# 5. Hard gate (DB form, fail-closed) + analytical floor.
# --------------------------------------------------------------------------- #
class TestHardGate:
    def test_no_resolved_id_no_commands_rejected(self, db_manager):
        """A cited id absent from the DB trail AND no supporting_commands -> REJECT."""
        mgr, store, state = db_manager
        state["audit"] = []  # nothing resolves
        res = mgr.record_finding(
            _finding("HIGH", audit_ids=["forensicrag-deadbeef-20260101-001"]),
            examiner_override="alice",
        )
        assert res["status"] == "REJECTED", res
        assert "no evidence trail" in res["error"]

    def test_analytical_supporting_command_floors_low(self, db_manager):
        """No resolved id but a supporting_command survives the gate at LOW."""
        mgr, store, state = db_manager
        state["audit"] = []
        res = mgr.record_finding(
            _finding("HIGH", audit_ids=[]),
            supporting_commands=[
                {"command": "analytical reasoning", "purpose": "triage",
                 "output_excerpt": "n/a"}
            ],
            examiner_override="alice",
        )
        assert res["status"] == "STAGED", res
        f = store.last_finding()
        assert f["confidence"] == "LOW"
        assert f["provenance_grade"] == "UNREFERENCED"


# --------------------------------------------------------------------------- #
# 6. Hash semantics: confidence IN the hash; grounding + derivation EXCLUDED.
# --------------------------------------------------------------------------- #
class TestHashSemantics:
    def test_confidence_in_hash_grounding_and_derivation_excluded(self, db_manager):
        mgr, store, state = db_manager
        state["audit"] = [
            _audit_row("rc-1", tool="run_command", backend="sift-core",
                       evidence_refs=["ev-uuid-1"]),
        ]
        state["sealed"] = [
            {"evidence_id": "ev-uuid-1", "path": "evidence/x.E01",
             "sha256": "a" * 64, "status": "sealed"}
        ]
        mgr.record_finding(_finding("HIGH", audit_ids=["rc-1"]),
                           examiner_override="alice")
        f = store.last_finding()
        stored = f["content_hash"]

        assert "grounding" in HASH_EXCLUDE_KEYS
        assert "confidence_derivation" in HASH_EXCLUDE_KEYS
        assert "confidence" not in HASH_EXCLUDE_KEYS

        assert compute_content_hash(f) == stored
        # Mutating grounding / derivation does NOT change the hash.
        mutated = dict(f)
        mutated["grounding"] = {"level": "ZZZ", "sources_count": 99}
        mutated["confidence_derivation"] = {"agent": "ZZZ"}
        assert compute_content_hash(mutated) == stored
        # Changing confidence ITSELF DOES change the hash (it is the recorded fact).
        changed = dict(f)
        changed["confidence"] = "MEDIUM"
        assert compute_content_hash(changed) != stored


# --------------------------------------------------------------------------- #
# 7. IOC propagation inherits the CLAMPED confidence.
# --------------------------------------------------------------------------- #
class TestIocPropagation:
    def test_extracted_ioc_inherits_clamped_low(self, db_manager):
        mgr, store, state = db_manager
        state["audit"] = [
            _audit_row("rc-1", tool="run_command", backend="sift-core",
                       evidence_refs=["ev-uuid-1"]),
        ]
        state["sealed"] = [
            {"evidence_id": "ev-uuid-1", "path": "evidence/x.E01",
             "sha256": "a" * 64, "status": "sealed"}
        ]
        finding = _finding("HIGH", audit_ids=["rc-1"])
        finding["observation"] = "Beacon to 203.0.113.45 observed"
        finding["iocs"] = ["203.0.113.45"]
        res = mgr.record_finding(finding, examiner_override="alice")
        assert res["status"] == "STAGED", res
        ioc = next(i for i in store.iocs.values() if i.get("value") == "203.0.113.45")
        # engaged + grounding 0 -> ceiling LOW; the IOC inherits the clamped LOW,
        # never the self-asserted HIGH.
        assert (ioc.get("confidence") or "").upper() == "LOW", ioc


# --------------------------------------------------------------------------- #
# 8. BE-6: SPECULATIVE purged; legacy SPECULATIVE normalizes to LOW.
# --------------------------------------------------------------------------- #
class TestSpeculativePurge:
    def test_normalize_confidence_collapses_speculative(self):
        assert normalize_confidence("SPECULATIVE") == "LOW"
        assert normalize_confidence("speculative") == "LOW"
        assert normalize_confidence("HIGH") == "HIGH"
        assert normalize_confidence("") == ""

    def test_conf_rank_treats_legacy_speculative_as_low(self):
        assert _conf_rank("SPECULATIVE") == _conf_rank("LOW")
        assert _conf_rank("LOW") > _conf_rank("MEDIUM") > _conf_rank("HIGH")

    def test_conf_ranks_has_no_speculative(self):
        from sift_core.ioc_helpers import _CONF_RANKS

        assert set(_CONF_RANKS) == {"HIGH", "MEDIUM", "LOW"}


# --------------------------------------------------------------------------- #
# 9. Clamp lives ONLY in record_finding (the agent path).
# --------------------------------------------------------------------------- #
class TestClampScope:
    def test_clamp_only_in_record_finding(self):
        rf_src = inspect.getsource(cm.CaseManager.record_finding)
        assert "_derive_confidence_ceiling" in rf_src
        # The helper is module-level (a single mapping site), callable standalone.
        assert _derive_confidence_ceiling(True, 0) == "LOW"
