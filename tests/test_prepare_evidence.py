"""Fail-on-revert tests for descriptor-pinned operator evidence preparation."""

from __future__ import annotations

import importlib.util
import os
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
PREPARE_EVIDENCE = REPO_ROOT / "scripts" / "prepare_evidence.py"
INSTALLER = REPO_ROOT / "install.sh"

_SPEC = importlib.util.spec_from_file_location("prepare_evidence", PREPARE_EVIDENCE)
assert _SPEC and _SPEC.loader
prepare_evidence = importlib.util.module_from_spec(_SPEC)
sys.modules[_SPEC.name] = prepare_evidence
_SPEC.loader.exec_module(prepare_evidence)


def _service_identity():
    return prepare_evidence.ServiceIdentity("sift-service", os.getuid(), os.getgid())


def _evidence_dir(tmp_path: Path) -> Path:
    evidence_dir = tmp_path / "evidence"
    evidence_dir.mkdir()
    evidence_dir.chmod(0o755)
    return evidence_dir


def _record_metadata_repairs(monkeypatch: pytest.MonkeyPatch) -> list[tuple[str, int, int] | tuple[str, int]]:
    repairs: list[tuple[str, int, int] | tuple[str, int]] = []
    monkeypatch.setattr(prepare_evidence, "_get_immutable_flags", lambda _fd: 0)
    monkeypatch.setattr(
        prepare_evidence,
        "os_fchown",
        lambda _fd, uid, gid: repairs.append(("chown", uid, gid)),
    )
    monkeypatch.setattr(
        prepare_evidence,
        "os_fchmod",
        lambda _fd, mode: repairs.append(("chmod", mode)),
    )
    return repairs


def test_prepare_repairs_only_the_descriptor_pinned_regular_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    evidence_dir = _evidence_dir(tmp_path)
    (evidence_dir / "root-copied.E01").write_bytes(b"test evidence")
    repairs = _record_metadata_repairs(monkeypatch)
    service = _service_identity()

    prepared = prepare_evidence.prepare_evidence_dir(evidence_dir, service)

    assert prepared == 1
    assert repairs == [("chown", service.uid, service.gid), ("chmod", 0o644)]


def test_prepare_validates_every_entry_before_changing_any_metadata(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    evidence_dir = _evidence_dir(tmp_path)
    first = evidence_dir / "first.E01"
    first.write_bytes(b"test evidence")
    os.link(first, evidence_dir / "linked.E01")
    repairs = _record_metadata_repairs(monkeypatch)

    with pytest.raises(prepare_evidence.PrepareEvidenceError, match="hard-linked"):
        prepare_evidence.prepare_evidence_dir(evidence_dir, _service_identity())

    assert repairs == []


def test_prepare_rejects_a_symlink_without_following_it(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    evidence_dir = _evidence_dir(tmp_path)
    target = tmp_path / "outside.E01"
    target.write_bytes(b"outside")
    os.symlink(target, evidence_dir / "link.E01")
    repairs = _record_metadata_repairs(monkeypatch)

    with pytest.raises(prepare_evidence.PrepareEvidenceError, match="symlink"):
        prepare_evidence.prepare_evidence_dir(evidence_dir, _service_identity())

    assert repairs == []


def test_prepare_rejects_immutable_entries_before_changing_any_metadata(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    evidence_dir = _evidence_dir(tmp_path)
    (evidence_dir / "sealed.E01").write_bytes(b"test evidence")
    repairs = _record_metadata_repairs(monkeypatch)
    monkeypatch.setattr(
        prepare_evidence,
        "_get_immutable_flags",
        lambda _fd: prepare_evidence.FS_IMMUTABLE_FL,
    )

    with pytest.raises(prepare_evidence.PrepareEvidenceError, match="immutable"):
        prepare_evidence.prepare_evidence_dir(evidence_dir, _service_identity())

    assert repairs == []


def test_prepare_requires_the_normal_service_owned_0755_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    evidence_dir = _evidence_dir(tmp_path)
    (evidence_dir / "root-copied.E01").write_bytes(b"test evidence")
    evidence_dir.chmod(0o700)
    repairs = _record_metadata_repairs(monkeypatch)

    with pytest.raises(prepare_evidence.PrepareEvidenceError, match="0755"):
        prepare_evidence.prepare_evidence_dir(evidence_dir, _service_identity())

    assert repairs == []


def test_prepare_rejects_a_symlinked_intermediate_active_case_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    cases_root = tmp_path / "cases"
    cases_root.mkdir()
    cases_root.chmod(0o755)
    target_case = tmp_path / "foreign-case"
    (target_case / "evidence").mkdir(parents=True)
    target_case.chmod(0o755)
    (target_case / "evidence").chmod(0o755)
    os.symlink(target_case, cases_root / "case-active")
    monkeypatch.setattr(prepare_evidence, "CASES_ROOT", cases_root)
    repairs = _record_metadata_repairs(monkeypatch)

    with pytest.raises(prepare_evidence.PrepareEvidenceError, match="canonical active case directory"):
        prepare_evidence.prepare_active_case_evidence("case-active", _service_identity())

    assert repairs == []


def test_main_loads_only_root_owned_dependencies_before_opening_the_control_plane(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[str] = []
    monkeypatch.setattr(prepare_evidence, "_require_installed_root_owned", lambda: None)
    monkeypatch.setattr(
        prepare_evidence.pwd,
        "getpwnam",
        lambda _name: SimpleNamespace(pw_uid=os.getuid(), pw_gid=os.getgid()),
    )
    monkeypatch.setattr(prepare_evidence, "_read_control_plane_dsn", lambda *_args: "dsn")
    monkeypatch.setattr(
        prepare_evidence,
        "_activate_root_owned_dependencies",
        lambda: calls.append("dependencies"),
    )
    monkeypatch.setattr(
        prepare_evidence,
        "_resolve_unsealed_active_case",
        lambda _dsn: calls.append("active-case") or "case-active",
    )
    monkeypatch.setattr(
        prepare_evidence,
        "prepare_active_case_evidence",
        lambda _case, _service: calls.append("prepare") or 1,
    )

    assert prepare_evidence.main([]) == 0
    assert calls == ["dependencies", "active-case", "prepare"]


def test_installer_copies_the_privileged_helper_to_a_root_owned_system_path() -> None:
    installer = INSTALLER.read_text(encoding="utf-8")

    assert 'destination="/usr/local/lib/sift/prepare_evidence.py"' in installer
    assert 'install -d -m 755 -o root -g root /usr/local/lib/sift' in installer
    assert 'install -m 755 -o root -g root "$source" "$destination"' in installer
    assert 'destination_deps="/usr/local/lib/sift/prepare-evidence-python"' in installer
    assert 'cp -aL "$source_deps"/psycopg' in installer
