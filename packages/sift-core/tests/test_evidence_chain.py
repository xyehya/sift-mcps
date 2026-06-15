"""Tests for sift_core.evidence_chain."""

import hashlib
import json
import os

import pytest

from sift_core.evidence_chain import (
    ChainStatus,
    anchor_manifest,
    chain_status,
    compute_manifest_hash,
    diff_manifest,
    hash_file,
    ignore_file,
    init_evidence_chain,
    load_anchor_proof,
    load_ledger,
    load_manifest,
    retire_file,
    scan_evidence_dir,
    seal_manifest,
    verify_chain_hmac,
    verify_chain_integrity,
)

_KEY = b"test-derived-key-32bytes-padding!"  # 32-byte test key


@pytest.fixture
def case_dir(tmp_path):
    (tmp_path / "evidence").mkdir()
    (tmp_path / "CASE.yaml").write_text("case_id: test-case-001\ntitle: Test\nexaminer: alice\n")
    return tmp_path


@pytest.fixture
def initialized(case_dir):
    init_evidence_chain(case_dir)
    return case_dir


# ---------------------------------------------------------------------------
# init_evidence_chain
# ---------------------------------------------------------------------------

class TestInitEvidenceChain:
    def test_creates_manifest(self, case_dir):
        init_evidence_chain(case_dir)
        assert (case_dir / "evidence-manifest.json").exists()

    def test_creates_ledger(self, case_dir):
        init_evidence_chain(case_dir)
        assert (case_dir / "evidence-ledger.jsonl").exists()

    def test_manifest_version_zero(self, case_dir):
        init_evidence_chain(case_dir)
        m = load_manifest(case_dir)
        assert m["version"] == 0
        assert m["files"] == []

    def test_manifest_hash_is_valid(self, case_dir):
        init_evidence_chain(case_dir)
        m = load_manifest(case_dir)
        assert m["manifest_hash"] == compute_manifest_hash(m)

    def test_idempotent(self, case_dir):
        init_evidence_chain(case_dir)
        original = load_manifest(case_dir)["manifest_hash"]
        init_evidence_chain(case_dir)  # second call
        assert load_manifest(case_dir)["manifest_hash"] == original


# ---------------------------------------------------------------------------
# compute_manifest_hash
# ---------------------------------------------------------------------------

class TestComputeManifestHash:
    def test_deterministic(self, initialized):
        m = load_manifest(initialized)
        assert compute_manifest_hash(m) == compute_manifest_hash(m)

    def test_excludes_manifest_hash_field(self):
        m = {"version": 1, "files": [], "manifest_hash": "sha256:ignored", "case_id": "x",
             "created_at": "t", "created_by": "a", "previous_manifest_hash": ""}
        h1 = compute_manifest_hash(m)
        m2 = dict(m)
        m2["manifest_hash"] = "sha256:different"
        assert compute_manifest_hash(m2) == h1

    def test_sensitive_to_content(self):
        m1 = {"version": 1, "files": [], "manifest_hash": "", "case_id": "a",
              "created_at": "t", "created_by": "x", "previous_manifest_hash": ""}
        m2 = dict(m1)
        m2["case_id"] = "b"
        assert compute_manifest_hash(m1) != compute_manifest_hash(m2)

    def test_returns_sha256_prefix(self):
        m = {"version": 0, "files": [], "manifest_hash": "", "case_id": "x",
             "created_at": "t", "created_by": "", "previous_manifest_hash": ""}
        assert compute_manifest_hash(m).startswith("sha256:")


# ---------------------------------------------------------------------------
# hash_file
# ---------------------------------------------------------------------------

class TestHashFile:
    def test_matches_hashlib(self, tmp_path):
        f = tmp_path / "file.bin"
        f.write_bytes(b"hello evidence")
        expected = hashlib.sha256(b"hello evidence").hexdigest()
        assert hash_file(f) == expected

    def test_large_file_streams(self, tmp_path):
        f = tmp_path / "large.bin"
        data = b"x" * (200 * 1024)
        f.write_bytes(data)
        expected = hashlib.sha256(data).hexdigest()
        assert hash_file(f) == expected


# ---------------------------------------------------------------------------
# scan_evidence_dir
# ---------------------------------------------------------------------------

class TestScanEvidenceDir:
    def test_finds_files(self, case_dir):
        (case_dir / "evidence" / "disk.E01").write_bytes(b"image data")
        result = scan_evidence_dir(case_dir)
        assert len(result) == 1
        assert result[0]["path"] == "evidence/disk.E01"
        assert result[0]["bytes"] == len(b"image data")

    def test_skips_directories(self, case_dir):
        (case_dir / "evidence" / "subdir").mkdir()
        result = scan_evidence_dir(case_dir)
        assert result == []

    def test_skips_symlinks(self, case_dir, tmp_path):
        target = tmp_path / "external.bin"
        target.write_bytes(b"data")
        link = case_dir / "evidence" / "link.bin"
        link.symlink_to(target)
        result = scan_evidence_dir(case_dir)
        assert result == []

    def test_recursive(self, case_dir):
        (case_dir / "evidence" / "host1").mkdir()
        (case_dir / "evidence" / "host1" / "mem.raw").write_bytes(b"mem")
        result = scan_evidence_dir(case_dir)
        assert any("host1/mem.raw" in r["path"] for r in result)

    def test_no_evidence_dir(self, tmp_path):
        assert scan_evidence_dir(tmp_path) == []


# ---------------------------------------------------------------------------
# diff_manifest
# ---------------------------------------------------------------------------

class TestDiffManifest:
    def _make_manifest(self, case_dir, files):
        return {
            "version": 1,
            "files": [
                {"path": f["path"], "bytes": f["bytes"], "sha256": "x", "status": "ACTIVE"}
                for f in files
            ],
        }

    def test_ok_when_all_match(self, case_dir):
        ev = case_dir / "evidence" / "a.bin"
        ev.write_bytes(b"data")
        m = self._make_manifest(case_dir, [{"path": "evidence/a.bin", "bytes": 4}])
        result = diff_manifest(case_dir, m)
        assert result["status"] == ChainStatus.OK
        assert "evidence/a.bin" in result["ok"]

    def test_missing(self, case_dir):
        m = self._make_manifest(case_dir, [{"path": "evidence/gone.bin", "bytes": 10}])
        result = diff_manifest(case_dir, m)
        assert result["status"] == ChainStatus.MISSING
        assert "evidence/gone.bin" in result["missing"]

    def test_modified_on_size_change(self, case_dir):
        ev = case_dir / "evidence" / "b.bin"
        ev.write_bytes(b"newdata")
        m = self._make_manifest(case_dir, [{"path": "evidence/b.bin", "bytes": 100}])
        result = diff_manifest(case_dir, m)
        assert result["status"] == ChainStatus.MODIFIED
        assert "evidence/b.bin" in result["modified"]

    def test_unregistered(self, case_dir):
        (case_dir / "evidence" / "extra.bin").write_bytes(b"x")
        m = {"version": 1, "files": []}
        result = diff_manifest(case_dir, m)
        assert result["status"] == ChainStatus.UNREGISTERED
        assert "evidence/extra.bin" in result["unregistered"]

    def test_ignored_entries_excluded(self, case_dir):
        m = {"version": 1, "files": [
            {"path": "evidence/ignored.bin", "bytes": 0, "sha256": "", "status": "IGNORED"}
        ]}
        result = diff_manifest(case_dir, m)
        assert result["status"] == ChainStatus.OK

    def test_priority_missing_over_unregistered(self, case_dir):
        (case_dir / "evidence" / "extra.bin").write_bytes(b"x")
        m = self._make_manifest(case_dir, [{"path": "evidence/gone.bin", "bytes": 10}])
        result = diff_manifest(case_dir, m)
        assert result["status"] == ChainStatus.MISSING


# ---------------------------------------------------------------------------
# chain_status
# ---------------------------------------------------------------------------

class TestChainStatus:
    def test_unsealed_on_v0(self, initialized):
        result = chain_status(initialized)
        assert result["status"] == ChainStatus.UNSEALED

    def test_ok_after_seal(self, initialized):
        ev = initialized / "evidence" / "disk.E01"
        ev.write_bytes(b"disk image")
        seal_manifest(initialized, [{"path": "evidence/disk.E01"}], "alice", _KEY)
        result = chain_status(initialized)
        assert result["status"] == ChainStatus.OK
        assert result["manifest_version"] == 1

    def test_ledger_error_on_manifest_hash_tamper(self, initialized):
        ev = initialized / "evidence" / "x.bin"
        ev.write_bytes(b"data")
        seal_manifest(initialized, [{"path": "evidence/x.bin"}], "alice", _KEY)
        # Tamper with manifest
        m = load_manifest(initialized)
        m["files"][0]["sha256"] = "tampered"
        (initialized / "evidence-manifest.json").write_text(json.dumps(m))
        result = chain_status(initialized)
        assert result["status"] == ChainStatus.LEDGER_ERROR

    def test_missing_after_file_removed(self, initialized):
        from sift_core.evidence_chain import _set_immutable
        ev = initialized / "evidence" / "del.bin"
        ev.write_bytes(b"data")
        seal_manifest(initialized, [{"path": "evidence/del.bin"}], "alice", _KEY)
        _set_immutable(ev, False)
        ev.unlink()
        result = chain_status(initialized)
        assert result["status"] == ChainStatus.MISSING

    def test_unregistered_file_detected(self, initialized):
        seal_manifest(initialized, [], "alice", _KEY)
        (initialized / "evidence" / "surprise.bin").write_bytes(b"unknown")
        result = chain_status(initialized)
        assert result["status"] == ChainStatus.UNREGISTERED

    def test_no_manifest_file(self, case_dir):
        result = chain_status(case_dir)
        assert result["status"] == ChainStatus.UNSEALED


# ---------------------------------------------------------------------------
# seal_manifest
# ---------------------------------------------------------------------------

class TestSealManifest:
    def test_increments_version(self, initialized):
        seal_manifest(initialized, [], "alice", _KEY)
        m = load_manifest(initialized)
        assert m["version"] == 1

    def test_hashes_file_correctly(self, initialized):
        ev = initialized / "evidence" / "sample.bin"
        ev.write_bytes(b"forensic data")
        seal_manifest(initialized, [{"path": "evidence/sample.bin"}], "alice", _KEY)
        m = load_manifest(initialized)
        entry = m["files"][0]
        assert entry["sha256"] == hashlib.sha256(b"forensic data").hexdigest()

    def test_records_examiner(self, initialized):
        ev = initialized / "evidence" / "f.bin"
        ev.write_bytes(b"x")
        seal_manifest(initialized, [{"path": "evidence/f.bin", "source": "USB-123"}], "alice", _KEY)
        m = load_manifest(initialized)
        assert m["files"][0]["registered_by"] == "alice"
        assert m["files"][0]["source"] == "USB-123"

    def test_appends_ledger_event(self, initialized):
        ev = initialized / "evidence" / "ev.bin"
        ev.write_bytes(b"evidence")
        seal_manifest(initialized, [{"path": "evidence/ev.bin"}], "alice", _KEY)
        ledger = load_ledger(initialized)
        assert len(ledger) == 1
        assert ledger[0]["event"] == "MANIFEST_SEALED"
        assert "evidence/ev.bin" in ledger[0]["files_added"]

    def test_ledger_has_hmac(self, initialized):
        seal_manifest(initialized, [], "alice", _KEY)
        ledger = load_ledger(initialized)
        assert "hmac" in ledger[0]
        assert len(ledger[0]["hmac"]) == 64

    def test_manifest_hash_chain(self, initialized):
        ev1 = initialized / "evidence" / "a.bin"
        ev1.write_bytes(b"a")
        seal_manifest(initialized, [{"path": "evidence/a.bin"}], "alice", _KEY)
        m1_hash = load_manifest(initialized)["manifest_hash"]

        ev2 = initialized / "evidence" / "b.bin"
        ev2.write_bytes(b"b")
        seal_manifest(initialized, [{"path": "evidence/b.bin"}], "alice", _KEY)
        m2 = load_manifest(initialized)

        assert m2["previous_manifest_hash"] == m1_hash
        assert m2["version"] == 2

    def test_seal_empty_case(self, initialized):
        m = seal_manifest(initialized, [], "alice", _KEY)
        assert m["version"] == 1
        assert m["files"] == []
        ledger = load_ledger(initialized)
        assert ledger[0]["files_added"] == []

    def test_file_not_found_raises(self, initialized):
        with pytest.raises(FileNotFoundError):
            seal_manifest(initialized, [{"path": "evidence/ghost.bin"}], "alice", _KEY)

    def test_directory_rejected(self, initialized):
        (initialized / "evidence" / "subdir").mkdir()
        with pytest.raises(ValueError, match="directory"):
            seal_manifest(initialized, [{"path": "evidence/subdir"}], "alice", _KEY)

    def test_path_traversal_rejected(self, initialized):
        with pytest.raises(ValueError):
            seal_manifest(initialized, [{"path": "../../etc/passwd"}], "alice", _KEY)

    def test_carries_ignored_entries(self, initialized):
        ev = initialized / "evidence" / "real.bin"
        ev.write_bytes(b"real")
        seal_manifest(initialized, [{"path": "evidence/real.bin"}], "alice", _KEY)
        ignore_file(initialized, "evidence/noise.txt", "alice", _KEY, "not evidence")
        ev2 = initialized / "evidence" / "real2.bin"
        ev2.write_bytes(b"real2")
        seal_manifest(initialized, [{"path": "evidence/real2.bin"}], "alice", _KEY)
        m = load_manifest(initialized)
        statuses = {f["path"]: f["status"] for f in m["files"]}
        assert statuses.get("evidence/noise.txt") == "IGNORED"
        assert statuses.get("evidence/real2.bin") == "ACTIVE"


# ---------------------------------------------------------------------------
# ignore_file
# ---------------------------------------------------------------------------

class TestIgnoreFile:
    def test_adds_ignored_entry_to_manifest(self, initialized):
        ignore_file(initialized, "evidence/noise.bin", "alice", _KEY, "not evidence")
        m = load_manifest(initialized)
        assert m["version"] == 1
        ignored = [f for f in m["files"] if f["status"] == "IGNORED"]
        assert len(ignored) == 1
        assert ignored[0]["path"] == "evidence/noise.bin"
        assert ignored[0]["description"] == "not evidence"

    def test_appends_file_ignored_event(self, initialized):
        ignore_file(initialized, "evidence/noise.bin", "alice", _KEY, "stray file")
        ledger = load_ledger(initialized)
        assert ledger[0]["event"] == "FILE_IGNORED"
        assert ledger[0]["path"] == "evidence/noise.bin"

    def test_ignored_file_not_flagged_as_unregistered(self, initialized):
        (initialized / "evidence" / "noise.bin").write_bytes(b"noise")
        ignore_file(initialized, "evidence/noise.bin", "alice", _KEY, "noise")
        result = chain_status(initialized)
        assert "evidence/noise.bin" not in result.get("issues", [])

    def test_raises_without_manifest(self, case_dir):
        with pytest.raises(ValueError, match="init_evidence_chain"):
            ignore_file(case_dir, "evidence/x.bin", "alice", _KEY, "reason")


# ---------------------------------------------------------------------------
# verify_chain_integrity
# ---------------------------------------------------------------------------

class TestVerifyChainIntegrity:
    def test_ok_after_seal(self, initialized):
        ev = initialized / "evidence" / "f.bin"
        ev.write_bytes(b"data")
        seal_manifest(initialized, [{"path": "evidence/f.bin"}], "alice", _KEY)
        result = verify_chain_integrity(initialized)
        assert result["ok"] is True
        assert result["events"] == 1

    def test_fails_on_manifest_hash_tamper(self, initialized):
        seal_manifest(initialized, [], "alice", _KEY)
        m = load_manifest(initialized)
        m["version"] = 99  # tamper without updating hash
        (initialized / "evidence-manifest.json").write_text(json.dumps(m))
        result = verify_chain_integrity(initialized)
        assert result["ok"] is False

    def test_fails_on_ledger_hash_chain_break(self, initialized):
        ev = initialized / "evidence" / "f.bin"
        ev.write_bytes(b"x")
        seal_manifest(initialized, [{"path": "evidence/f.bin"}], "alice", _KEY)
        ev2 = initialized / "evidence" / "g.bin"
        ev2.write_bytes(b"y")
        seal_manifest(initialized, [{"path": "evidence/g.bin"}], "alice", _KEY)
        # Tamper with first ledger event
        ledger = load_ledger(initialized)
        ledger[0]["new_manifest_hash"] = "sha256:tampered"
        ledger_path = initialized / "evidence-ledger.jsonl"
        os.chmod(ledger_path, 0o644)
        ledger_path.write_text("\n".join(json.dumps(e) for e in ledger) + "\n")
        result = verify_chain_integrity(initialized)
        assert result["ok"] is False

    def test_no_manifest_returns_error(self, case_dir):
        result = verify_chain_integrity(case_dir)
        assert result["ok"] is False


# ---------------------------------------------------------------------------
# verify_chain_hmac
# ---------------------------------------------------------------------------

class TestVerifyChainHmac:
    def test_ok_with_correct_key(self, initialized):
        seal_manifest(initialized, [], "alice", _KEY)
        result = verify_chain_hmac(initialized, _KEY)
        assert result["ok"] is True
        assert result["verified"] == 1

    def test_fails_with_wrong_key(self, initialized):
        seal_manifest(initialized, [], "alice", _KEY)
        wrong_key = b"wrong-key-32-bytes-padding-here!"
        result = verify_chain_hmac(initialized, wrong_key)
        assert result["ok"] is False
        assert result["failed"] == 1

    def test_multiple_events(self, initialized):
        seal_manifest(initialized, [], "alice", _KEY)
        ignore_file(initialized, "evidence/x.bin", "alice", _KEY, "noise")
        result = verify_chain_hmac(initialized, _KEY)
        assert result["ok"] is True
        assert result["verified"] == 2

    def test_empty_ledger(self, initialized):
        result = verify_chain_hmac(initialized, _KEY)
        assert result["ok"] is True
        assert result["verified"] == 0


# ---------------------------------------------------------------------------
# Path safety
# ---------------------------------------------------------------------------

class TestPathSafety:
    def test_path_traversal_blocked(self, initialized):
        from sift_core.evidence_chain import _resolve_evidence_path
        with pytest.raises(ValueError):
            _resolve_evidence_path(initialized, "../../etc/passwd")

    def test_valid_nested_path_ok(self, initialized):
        from sift_core.evidence_chain import _resolve_evidence_path
        (initialized / "evidence" / "sub").mkdir()
        (initialized / "evidence" / "sub" / "file.bin").write_bytes(b"x")
        resolved = _resolve_evidence_path(initialized, "evidence/sub/file.bin")
        assert resolved.exists()


# ---------------------------------------------------------------------------
# retire_file
# ---------------------------------------------------------------------------

def _seal_active_file(case_dir, filename="evidence/sample.bin", content=b"DATA"):
    """Helper: write file + seal it; returns the relative path."""
    (case_dir / filename).write_bytes(content)
    seal_manifest(case_dir, [{"path": filename}], "alice", _KEY)
    return filename


class TestRetireFile:
    def test_marks_file_retired_in_manifest(self, initialized):
        path = _seal_active_file(initialized)
        retire_file(initialized, path, "corrupt acquisition", "alice", _KEY)
        m = load_manifest(initialized)
        retired = [f for f in m["files"] if f.get("status") == "RETIRED"]
        assert len(retired) == 1
        assert retired[0]["path"] == path
        assert retired[0]["retire_reason"] == "corrupt acquisition"
        assert retired[0]["retired_by"] == "alice"

    def test_increments_manifest_version(self, initialized):
        path = _seal_active_file(initialized)
        before = load_manifest(initialized)["version"]
        retire_file(initialized, path, "bad image", "alice", _KEY)
        after = load_manifest(initialized)["version"]
        assert after == before + 1

    def test_appends_file_retired_ledger_event(self, initialized):
        path = _seal_active_file(initialized)
        retire_file(initialized, path, "bad image", "alice", _KEY)
        ledger = load_ledger(initialized)
        last = ledger[-1]
        assert last["event"] == "FILE_RETIRED"
        assert last["path"] == path
        assert last["reason"] == "bad image"
        assert last["approved_by"] == "alice"

    def test_ledger_event_hmac_verifies(self, initialized):
        path = _seal_active_file(initialized)
        retire_file(initialized, path, "bad image", "alice", _KEY)
        result = verify_chain_hmac(initialized, _KEY)
        assert result["ok"] is True
        assert result["failed"] == 0

    def test_hash_chain_intact_after_retire(self, initialized):
        path = _seal_active_file(initialized)
        retire_file(initialized, path, "reason", "alice", _KEY)
        result = verify_chain_integrity(initialized)
        assert result["ok"] is True

    def test_retired_path_excluded_from_diff(self, initialized):
        path = _seal_active_file(initialized)
        retire_file(initialized, path, "bad image", "alice", _KEY)
        (initialized / path).unlink()  # caller deletes after retire
        result = chain_status(initialized)
        assert result["status"] == ChainStatus.OK
        issues = result.get("issues", [])
        assert not any(path in i for i in issues)

    def test_retired_file_still_on_disk_shows_ok(self, initialized):
        path = _seal_active_file(initialized)
        retire_file(initialized, path, "reason", "alice", _KEY)
        # File still on disk (not deleted yet) — should still be OK
        result = chain_status(initialized)
        assert result["status"] == ChainStatus.OK

    def test_raises_on_unregistered_path(self, initialized):
        with pytest.raises(ValueError, match="not registered"):
            retire_file(initialized, "evidence/ghost.bin", "oops", "alice", _KEY)

    def test_raises_on_ignored_path(self, initialized):
        ignore_file(initialized, "evidence/noise.bin", "alice", _KEY, "stray")
        with pytest.raises(ValueError, match="IGNORED"):
            retire_file(initialized, "evidence/noise.bin", "bad reason", "alice", _KEY)

    def test_raises_on_already_retired_path(self, initialized):
        path = _seal_active_file(initialized)
        retire_file(initialized, path, "first retire", "alice", _KEY)
        with pytest.raises(ValueError, match="already RETIRED"):
            retire_file(initialized, path, "double retire", "alice", _KEY)

    def test_raises_without_manifest(self, case_dir):
        with pytest.raises(ValueError, match="init_evidence_chain"):
            retire_file(case_dir, "evidence/x.bin", "reason", "alice", _KEY)

    def test_preserves_other_active_files(self, initialized):
        (initialized / "evidence" / "keep.bin").write_bytes(b"KEEP")
        (initialized / "evidence" / "remove.bin").write_bytes(b"GONE")
        seal_manifest(initialized, [
            {"path": "evidence/keep.bin"},
            {"path": "evidence/remove.bin"},
        ], "alice", _KEY)
        retire_file(initialized, "evidence/remove.bin", "bad", "alice", _KEY)
        m = load_manifest(initialized)
        statuses = {f["path"]: f["status"] for f in m["files"]}
        assert statuses["evidence/keep.bin"] == "ACTIVE"
        assert statuses["evidence/remove.bin"] == "RETIRED"


# ---------------------------------------------------------------------------
# diff_manifest — RETIRED exclusion
# ---------------------------------------------------------------------------

class TestDiffManifestRetiredExclusion:
    def test_retired_entry_excluded_from_registered(self, initialized):
        path = _seal_active_file(initialized)
        retire_file(initialized, path, "bad", "alice", _KEY)
        m = load_manifest(initialized)
        (initialized / path).unlink()
        diff = diff_manifest(initialized, m)
        assert path not in diff["missing"]
        assert path not in diff["ok"]

    def test_retired_file_on_disk_not_counted_unregistered(self, initialized):
        path = _seal_active_file(initialized)
        retire_file(initialized, path, "bad", "alice", _KEY)
        m = load_manifest(initialized)
        # File still on disk — should NOT appear as unregistered
        diff = diff_manifest(initialized, m)
        assert path not in diff["unregistered"]


# ---------------------------------------------------------------------------
# anchor_manifest / load_anchor_proof (Phase 16e)
# ---------------------------------------------------------------------------

class TestAnchorManifest:
    def test_writes_proof_file_no_keypair(self, initialized):
        """Proof file written with solana_tx=None when no keypair given."""
        f = initialized / "evidence" / "data.bin"
        f.write_bytes(b"x" * 32)
        manifest = seal_manifest(initialized, [{"path": "evidence/data.bin"}], "alice", _KEY)
        ledger = load_ledger(initialized)
        proof = anchor_manifest(initialized, manifest, ledger)
        assert (initialized / "evidence-anchor-v1.json").exists()
        assert proof["schema"] == "sift.evidence-anchor.v1"
        assert proof["manifest_version"] == 1
        assert proof["solana_tx"] is None
        assert proof["confirmed"] is False
        assert proof["manifest_hash"] == manifest["manifest_hash"]

    def test_anchor_payload_format(self, initialized):
        """Payload contains SIFT prefix with manifest and ledger tip fragments."""
        f = initialized / "evidence" / "data.bin"
        f.write_bytes(b"hello")
        manifest = seal_manifest(initialized, [{"path": "evidence/data.bin"}], "alice", _KEY)
        ledger = load_ledger(initialized)
        proof = anchor_manifest(initialized, manifest, ledger)
        assert proof["anchor_payload"].startswith("SIFT|")
        parts = proof["anchor_payload"].split("|")
        assert len(parts) == 3
        assert len(parts[1]) == 16
        assert len(parts[2]) == 16

    def test_graceful_degradation_missing_solders(self, initialized, monkeypatch):
        """If solders import fails, proof is still written without tx."""
        import builtins
        real_import = builtins.__import__

        def mock_import(name, *args, **kwargs):
            if name == "solders.keypair":
                raise ImportError("no solders")
            return real_import(name, *args, **kwargs)

        monkeypatch.setattr(builtins, "__import__", mock_import)
        f = initialized / "evidence" / "data.bin"
        f.write_bytes(b"test")
        manifest = seal_manifest(initialized, [{"path": "evidence/data.bin"}], "alice", _KEY)
        ledger = load_ledger(initialized)
        proof = anchor_manifest(initialized, manifest, ledger, keypair_path="/fake/keypair.json")
        assert proof["solana_tx"] is None
        assert (initialized / "evidence-anchor-v1.json").exists()

    def test_load_anchor_proof_returns_none_when_missing(self, initialized):
        assert load_anchor_proof(initialized, 1) is None

    def test_load_anchor_proof_roundtrip(self, initialized):
        f = initialized / "evidence" / "data.bin"
        f.write_bytes(b"y" * 8)
        manifest = seal_manifest(initialized, [{"path": "evidence/data.bin"}], "alice", _KEY)
        ledger = load_ledger(initialized)
        anchor_manifest(initialized, manifest, ledger)
        loaded = load_anchor_proof(initialized, 1)
        assert loaded is not None
        assert loaded["manifest_version"] == 1
        assert loaded["solana_tx"] is None

    def test_anchor_db_proof_writes_no_file_and_derives_payload(self, initialized):
        """anchor_db_proof derives payload from DB material, writes no case file."""
        from sift_core.evidence_chain import anchor_db_proof

        before = set(p.name for p in initialized.iterdir())
        proof = anchor_db_proof(
            manifest_version=2,
            manifest_hash="sha256:" + "a" * 64,
            ledger_tip_hash="sha256:" + "b" * 64,
        )
        after = set(p.name for p in initialized.iterdir())
        # No evidence-anchor-v*.json (or any new file) written: DB records it.
        assert before == after
        assert proof["schema"] == "sift.evidence-anchor.v1"
        assert proof["manifest_version"] == 2
        assert proof["solana_tx"] is None
        assert proof["confirmed"] is False
        assert proof["anchor_payload"].startswith("SIFT|")
        parts = proof["anchor_payload"].split("|")
        assert len(parts) == 3 and len(parts[1]) == 16 and len(parts[2]) == 16

    def test_anchor_db_proof_degrades_without_keypair(self, initialized):
        from sift_core.evidence_chain import anchor_db_proof

        proof = anchor_db_proof(
            manifest_version=1,
            manifest_hash="sha256:" + "c" * 64,
            ledger_tip_hash="",
            keypair_path=None,
        )
        assert proof["solana_tx"] is None
        assert proof["confirmed"] is False

    def test_each_version_gets_own_proof_file(self, initialized):
        for i in range(2):
            fname = f"evidence/file{i}.bin"
            (initialized / fname).write_bytes(b"v" * (i + 1))
            manifest = seal_manifest(initialized, [{"path": fname}], "alice", _KEY)
            ledger = load_ledger(initialized)
            anchor_manifest(initialized, manifest, ledger)
        assert (initialized / "evidence-anchor-v1.json").exists()
        assert (initialized / "evidence-anchor-v2.json").exists()
        p1 = load_anchor_proof(initialized, 1)
        p2 = load_anchor_proof(initialized, 2)
        assert p1["manifest_version"] == 1
        assert p2["manifest_version"] == 2
        assert p1["manifest_hash"] != p2["manifest_hash"]


# ---------------------------------------------------------------------------
# harden_sealed_evidence (B-MVP-048)
# ---------------------------------------------------------------------------

class TestHardenSealedEvidence:
    def _make_evidence(self, case_dir, name="disk.E01", data=b"bytes"):
        p = case_dir / "evidence" / name
        p.write_bytes(data)
        return p

    def test_success_in_process_sets_immutable(self, initialized, monkeypatch):
        import sift_core.evidence_chain as ec

        self._make_evidence(initialized)
        # No helper configured -> in-process path.
        monkeypatch.setenv("SIFT_EVIDENCE_HARDEN_HELPER", "off")
        calls = {}

        def fake_set_immutable(path, immutable):
            calls["set"] = (str(path), immutable)
            return True

        monkeypatch.setattr(ec, "_set_immutable", fake_set_immutable)
        monkeypatch.setattr(ec, "get_immutable_flag", lambda p: True)
        # Pretend the file is already service-owned so no warning path is taken.
        monkeypatch.setattr(ec, "_file_owner_name", lambda p: ec.DEFAULT_SERVICE_USER)

        results = ec.harden_sealed_evidence(initialized, ["evidence/disk.E01"])
        assert calls["set"][1] is True
        assert results == [
            {"path": "evidence/disk.E01", "owner": ec.DEFAULT_SERVICE_USER, "immutable": True}
        ]

    def test_uses_helper_when_present(self, initialized, monkeypatch):
        import sift_core.evidence_chain as ec

        self._make_evidence(initialized)
        monkeypatch.setattr(ec, "_harden_helper_path", lambda: "/usr/local/sbin/sift-seal-evidence")
        used = {}

        def fake_helper(helper, abs_path, service_user):
            used["called"] = (helper, str(abs_path), service_user)

        monkeypatch.setattr(ec, "_harden_via_helper", fake_helper)
        # After the (mocked) helper runs, the file appears owned + immutable.
        monkeypatch.setattr(ec, "_file_owner_name", lambda p: "sift-service")
        monkeypatch.setattr(ec, "get_immutable_flag", lambda p: True)
        # _set_immutable must NOT be called when the helper is used.
        monkeypatch.setattr(
            ec, "_set_immutable", lambda *a, **k: pytest.fail("_set_immutable used with helper")
        )

        results = ec.harden_sealed_evidence(initialized, ["evidence/disk.E01"])
        assert used["called"][2] == "sift-service"
        assert results[0]["immutable"] is True

    def test_fails_closed_when_immutable_cannot_be_set(self, initialized, monkeypatch):
        import sift_core.evidence_chain as ec

        self._make_evidence(initialized)
        monkeypatch.setenv("SIFT_EVIDENCE_HARDEN_HELPER", "off")
        # Simulate unprivileged process: ioctl SETFLAGS denied.
        monkeypatch.setattr(ec, "_set_immutable", lambda p, imm: False)

        with pytest.raises(ec.EvidenceHardeningError):
            ec.harden_sealed_evidence(initialized, ["evidence/disk.E01"])

    def test_fails_closed_when_flag_absent_after_helper(self, initialized, monkeypatch):
        import sift_core.evidence_chain as ec

        self._make_evidence(initialized)
        monkeypatch.setattr(ec, "_harden_helper_path", lambda: "/usr/local/sbin/sift-seal-evidence")
        monkeypatch.setattr(ec, "_harden_via_helper", lambda *a, **k: None)
        monkeypatch.setattr(ec, "_file_owner_name", lambda p: "sift-service")
        # Helper "succeeded" but the flag is not actually present -> fail closed.
        monkeypatch.setattr(ec, "get_immutable_flag", lambda p: False)

        with pytest.raises(ec.EvidenceHardeningError):
            ec.harden_sealed_evidence(initialized, ["evidence/disk.E01"])

    def test_require_owner_raises_when_not_service_owned(self, initialized, monkeypatch):
        import sift_core.evidence_chain as ec

        self._make_evidence(initialized)
        monkeypatch.setenv("SIFT_EVIDENCE_HARDEN_HELPER", "off")
        monkeypatch.setattr(ec, "_set_immutable", lambda p, imm: True)
        monkeypatch.setattr(ec, "get_immutable_flag", lambda p: True)
        monkeypatch.setattr(ec, "_file_owner_name", lambda p: "root")

        with pytest.raises(ec.EvidenceHardeningError):
            ec.harden_sealed_evidence(
                initialized, ["evidence/disk.E01"], require_owner=True
            )

    def test_path_traversal_rejected(self, initialized, monkeypatch):
        import sift_core.evidence_chain as ec

        monkeypatch.setenv("SIFT_EVIDENCE_HARDEN_HELPER", "off")
        with pytest.raises(ValueError):
            ec.harden_sealed_evidence(initialized, ["../../etc/passwd"])

    def test_symlink_rejected(self, initialized, monkeypatch):
        import sift_core.evidence_chain as ec

        monkeypatch.setenv("SIFT_EVIDENCE_HARDEN_HELPER", "off")
        target = initialized / "evidence" / "real.bin"
        target.write_bytes(b"x")
        link = initialized / "evidence" / "link.bin"
        link.symlink_to(target)
        # A symlink escaping evidence/ would be caught by _resolve_evidence_path;
        # an in-tree symlink is rejected by the explicit symlink guard.
        with pytest.raises((ec.EvidenceHardeningError, ValueError)):
            ec.harden_sealed_evidence(initialized, ["evidence/link.bin"])

    def test_missing_file_rejected(self, initialized, monkeypatch):
        import sift_core.evidence_chain as ec

        monkeypatch.setenv("SIFT_EVIDENCE_HARDEN_HELPER", "off")
        with pytest.raises(ec.EvidenceHardeningError):
            ec.harden_sealed_evidence(initialized, ["evidence/nope.bin"])

    def test_helper_missing_path_is_error(self, initialized, monkeypatch):
        import sift_core.evidence_chain as ec

        self._make_evidence(initialized)
        monkeypatch.setenv("SIFT_EVIDENCE_HARDEN_HELPER", "/nonexistent/helper")
        with pytest.raises(ec.EvidenceHardeningError):
            ec.harden_sealed_evidence(initialized, ["evidence/disk.E01"])
