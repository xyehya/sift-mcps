"""Fail-on-revert contract for the pathless custody-delete broker."""

from __future__ import annotations

import hashlib
import json
import os
import pwd
import runpy
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest
from _installer_support import REPO_ROOT

HELPER = REPO_ROOT / "scripts" / "sift-custody-delete-broker"
SETUP = REPO_ROOT / "scripts" / "setup-custody-delete-broker.sh"
INSTALLER = REPO_ROOT / "install.sh"
HARDENING = REPO_ROOT / "lib" / "hardening.sh"
MIGRATIONS_LIB = REPO_ROOT / "lib" / "migrations.sh"
UNINSTALLER = REPO_ROOT / "scripts" / "uninstall.sh"
GATEWAY_PROFILE = REPO_ROOT / "configs" / "apparmor" / "sift-gateway.template"
BROKER_PROFILE = REPO_ROOT / "configs" / "apparmor" / "sift-custody-delete-broker.template"
MIGRATION = REPO_ROOT / "supabase" / "migrations" / "202607145200_custody_delete_broker_receipts.sql"
AUTHORIZE_REPAIR_MIGRATION = (
    REPO_ROOT
    / "supabase"
    / "migrations"
    / "202607145300_custody_delete_broker_authorize_shape.sql"
)
LATEST_INDEX = REPO_ROOT / "docs" / "latest" / "README.md"
CONTROL_PLANE_DOC = REPO_ROOT / "docs" / "latest" / "08 - Control Plane.md"


def _module() -> dict:
    return runpy.run_path(str(HELPER))


def test_interface_is_pathless_and_profile_bound() -> None:
    source = HELPER.read_text(encoding="utf-8")
    setup = SETUP.read_text(encoding="utf-8")
    installer = INSTALLER.read_text(encoding="utf-8")
    hardening = HARDENING.read_text(encoding="utf-8")
    migrations_lib = MIGRATIONS_LIB.read_text(encoding="utf-8")
    uninstaller = UNINSTALLER.read_text(encoding="utf-8")
    gateway = GATEWAY_PROFILE.read_text(encoding="utf-8")
    broker = BROKER_PROFILE.read_text(encoding="utf-8")

    assert 'REQUEST_KEYS = {"schema_version", "operation_id", "runner_instance_id"}' in source
    assert 'EXPECTED_PROFILE = "sift-custody-delete-broker (enforce)"' in source
    assert "shell=True" not in source
    assert "/etc/sift/custody-delete-dsn" in source
    assert "/var/lib/sift/.sift/control-plane.env" not in source
    assert r'NOPASSWD: ${HELPER_DST} \"\"' in setup
    assert "${HELPER_DST} *" not in setup
    assert "visudo" in setup
    assert "install -o root -g root -m 0755" in setup
    assert "sift-custody-delete-broker px -> sift-custody-delete-broker" in gateway
    assert "deny /cases/*/evidence/**                  w," in gateway
    assert "deny capability dac_override," in broker
    assert "deny capability dac_read_search," in broker
    assert "capability setuid," in broker
    assert "capability setgid," in broker
    assert "/etc/sift/custody-delete-dsn               r," in broker
    assert "/var/lib/sift/.sift/control-plane.env" not in broker
    assert "deny /bin/sh" in broker
    assert "configure_custody_delete_broker" in hardening
    assert installer.index("configure_custody_delete_broker") < installer.index("configure_apparmor")
    assert "provision_custody_delete_broker" in installer
    assert "sift_custody_delete_broker" in migrations_lib
    assert 'install -o root -g root -m 0600 "$tmp" "$destination"' in migrations_lib
    assert "has_schema_privilege(current_user,'app','USAGE')" in migrations_lib
    assert "has_table_privilege(current_user,'app.custody_operations','SELECT')" not in migrations_lib
    assert "has_table_privilege(current_user,'app.custody_delete_broker_receipts','SELECT')" not in migrations_lib
    assert migrations_lib.count("from pg_catalog.pg_class c") == 2
    assert migrations_lib.count("join pg_catalog.pg_namespace n") == 2
    assert migrations_lib.count("has_table_privilege(current_user,c.oid,'SELECT')") == 2
    assert "c.relname='custody_operations'" in migrations_lib
    assert "c.relname='custody_delete_broker_receipts'" in migrations_lib
    assert (
        "where n.nspname='app' and c.relname='custody_operations'),true)"
        in migrations_lib
    )
    assert (
        "where n.nspname='app' and c.relname='custody_delete_broker_receipts'),true)"
        in migrations_lib
    )
    assert migrations_lib.count("select current_user='sift_custody_delete_broker'") == 1
    assert migrations_lib.count("_custody_delete_broker_scope_valid") == 3
    assert "stale or mis-scoped; rotating" in migrations_lib
    for installed_path in (
        "/usr/local/sbin/sift-custody-delete-broker",
        "/etc/sift/custody-delete.json",
        "/etc/sift/custody-delete-dsn",
        "/etc/sudoers.d/sift-custody-delete-broker",
        "/etc/apparmor.d/sift-custody-delete-broker",
    ):
        assert installed_path in uninstaller


def test_broker_profile_allows_required_runtime_path_introspection_only() -> None:
    rules = {
        " ".join(line.split())
        for line in BROKER_PROFILE.read_text(encoding="utf-8").splitlines()
    }

    assert "/usr/local/sbin/ r," in rules
    assert "/proc/@{pid}/attr/current r," in rules
    assert "/usr/local/sbin/** r," not in rules
    assert "/proc/** r," not in rules


def test_broker_rebinds_uuid_to_postgres_and_durable_receipt() -> None:
    source = HELPER.read_text(encoding="utf-8")
    migration = MIGRATION.read_text(encoding="utf-8")

    for binding in (
        "sift_custody_broker.authorize",
        "sift_custody_broker.claim",
        "sift_custody_broker.complete",
        "missing_without_broker_claim",
        "os.O_NOFOLLOW",
        "regular_single_link_required",
        "immutable_evidence_refused",
        "os.fsync(evidence_fd)",
    ):
        assert binding in source
    assert "from app.custody_operations" not in source
    assert "**item" not in source
    assert "create table app.custody_delete_broker_receipts" in migration
    assert "create role sift_custody_delete_broker" in migration
    assert "create schema if not exists sift_custody_broker" in migration
    assert "grant usage on schema sift_custody_broker" in migration
    assert "grant usage on schema app" not in migration
    assert "security definer" in migration
    assert "completed_custody_delete_broker_receipt_required" in migration
    assert "custody_delete_broker_verified_required" in migration
    assert "jsonb_object_length(v_item)<>13" in migration
    assert "'original_version_id','original_sha256','original_bytes'" in migration
    assert "force row level security" in migration
    assert "revoke all" in migration


def test_broker_authorize_forward_repair_is_exact_shape_and_least_privilege() -> None:
    original = MIGRATION.read_text(encoding="utf-8").lower()
    repair = AUTHORIZE_REPAIR_MIGRATION.read_text(encoding="utf-8").lower()

    assert "jsonb_object_length(v_item)<>13" in original
    assert "jsonb_object_length(v_item)" not in repair
    assert (
        "create or replace function sift_custody_broker.authorize("
        in repair
    )
    assert "language plpgsql security definer set search_path=pg_catalog,app" in repair
    assert "not (v_item ?& array['evidence_object_id','display_path'" in repair
    assert "'st_dev','st_ino','st_nlink'])" in repair
    assert (
        "v_item-array['evidence_object_id','display_path'" in repair
    )
    assert "drop function" not in repair
    assert (
        "revoke all on function sift_custody_broker.authorize(uuid,text)\n"
        "  from public,anon,authenticated,service_role"
        in repair
    )
    assert (
        "grant execute on function sift_custody_broker.authorize(uuid,text)\n"
        "  to sift_custody_delete_broker"
        in repair
    )


def _install_fake_authority(monkeypatch, authority: dict) -> None:
    class Cursor:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

        def execute(self, *_args):
            return None

        def fetchone(self):
            return (authority,)

    class Connection:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

        def cursor(self):
            return Cursor()

    monkeypatch.setitem(sys.modules, "psycopg", SimpleNamespace(connect=lambda _dsn: Connection()))


def _valid_authority(cases_root: Path) -> dict:
    operation_id = "33333333-3333-3333-3333-333333333333"
    return {
        "operation_id": operation_id,
        "runner_instance_id": "process:test",
        "prepared_facts_sha256": "sha256:" + "a" * 64,
        "receipt_claimed": False,
        "receipt_completed": False,
        "receipt_runner_instance_id": None,
        "case_key": "case-a",
        "legacy_case_dir": str(cases_root / "case-a"),
        "display_path": "evidence/pending.bin",
        "item": {
            "evidence_object_id": "44444444-4444-4444-4444-444444444444",
            "display_path": "evidence/pending.bin",
            "prior_status": "detected",
            "prior_seal_status": "unsealed",
            "original_version_id": None,
            "original_sha256": None,
            "original_bytes": None,
            "present": True,
            "sha256": "sha256:" + "b" * 64,
            "bytes": 7,
            "st_dev": 1,
            "st_ino": 2,
            "st_nlink": 1,
        },
    }


@pytest.mark.parametrize(
    "collision",
    [
        "case_key",
        "name",
        "operation_id",
        "runner",
        "runner_instance_id",
        "prepared_facts_sha256",
        "receipt_claimed",
        "receipt_completed",
        "receipt_runner_instance_id",
    ],
)
def test_resolve_operation_rejects_prepared_fact_binding_collisions(
    monkeypatch, tmp_path: Path, collision: str
) -> None:
    module = _module()
    authority = _valid_authority(tmp_path)
    authority["item"][collision] = "attacker-controlled"
    _install_fake_authority(monkeypatch, authority)

    with pytest.raises(module["DeleteBrokerError"], match="operation_facts_invalid"):
        module["resolve_operation"](
            "unused",
            authority["operation_id"],
            authority["runner_instance_id"],
            tmp_path,
        )


def test_resolve_operation_accepts_exact_production_prepared_item(
    monkeypatch, tmp_path: Path
) -> None:
    module = _module()
    authority = _valid_authority(tmp_path)
    _install_fake_authority(monkeypatch, authority)

    operation = module["resolve_operation"](
        "unused",
        authority["operation_id"],
        authority["runner_instance_id"],
        tmp_path,
    )

    assert set(operation) == {
        "operation_id",
        "runner_instance_id",
        "prepared_facts_sha256",
        "receipt_claimed",
        "receipt_completed",
        "receipt_runner_instance_id",
        "case_key",
        "name",
        *module["DELETE_ITEM_KEYS"],
    }
    assert operation["case_key"] == "case-a"
    assert operation["name"] == "pending.bin"
    assert operation["original_version_id"] is None


def test_collision_cannot_redirect_delete_into_another_case(monkeypatch, tmp_path: Path) -> None:
    module = _module()
    cross_case_target = tmp_path / "case-b" / "evidence" / "protected.bin"
    cross_case_target.parent.mkdir(parents=True)
    cross_case_target.write_bytes(b"protect")
    target_info = cross_case_target.stat()
    authority = _valid_authority(tmp_path)
    authority["item"].update(
        {
            "case_key": "case-b",
            "name": "protected.bin",
            "sha256": "sha256:" + hashlib.sha256(b"protect").hexdigest(),
            "bytes": len(b"protect"),
            "st_dev": target_info.st_dev,
            "st_ino": target_info.st_ino,
        }
    )
    _install_fake_authority(monkeypatch, authority)
    delete_verified = module["delete_verified"]
    delete_verified.__globals__["_immutable"] = lambda _fd: False
    delete_verified.__globals__["claim_operation"] = lambda *_args: None
    delete_verified.__globals__["complete_operation"] = lambda *_args: None

    with pytest.raises(module["DeleteBrokerError"], match="operation_facts_invalid"):
        operation = module["resolve_operation"](
            "unused",
            authority["operation_id"],
            authority["runner_instance_id"],
            tmp_path,
        )
        delete_verified(operation, tmp_path, pwd.getpwuid(os.geteuid()), "unused")

    assert cross_case_target.read_bytes() == b"protect"


def test_live_control_plane_docs_derive_inventory_from_migration_source() -> None:
    combined = LATEST_INDEX.read_text(encoding="utf-8") + CONTROL_PLANE_DOC.read_text(
        encoding="utf-8"
    )

    assert "supabase/migrations/*.sql" in combined
    assert "source_of_truth: supabase/migrations/*.sql" in combined
    assert "25 migrations" not in combined
    assert "Migration Files (25 total)" not in combined
    assert "source_commit: eadb92b" not in combined


def test_parser_rejects_path_or_fact_arguments() -> None:
    module = _module()
    parse_request = module["parse_request"]
    good = {
        "schema_version": 1,
        "operation_id": "33333333-3333-3333-3333-333333333333",
        "runner_instance_id": "process:test",
    }
    assert parse_request(json.dumps(good).encode()) == good
    for extra in ("name", "case_key", "sha256", "bytes", "st_ino"):
        with pytest.raises(module["DeleteBrokerError"]):
            parse_request(json.dumps({**good, extra: "attacker-supplied"}).encode())


def test_missing_file_without_durable_claim_fails_closed(tmp_path: Path) -> None:
    module = _module()
    case_key = "case-1"
    evidence = tmp_path / case_key / "evidence"
    evidence.mkdir(parents=True)
    account = pwd.getpwuid(os.geteuid())
    operation = {
        "case_key": case_key,
        "name": "missing.bin",
        "receipt_claimed": False,
    }

    with pytest.raises(module["DeleteBrokerError"], match="missing_without_broker_claim"):
        module["delete_verified"](operation, tmp_path, account, "unused")


def test_missing_file_with_completed_receipt_is_idempotent_success(tmp_path: Path) -> None:
    module = _module()
    case_key = "case-1"
    (tmp_path / case_key / "evidence").mkdir(parents=True)
    operation = {
        "case_key": case_key,
        "name": "already-removed.bin",
        "receipt_claimed": True,
        "receipt_completed": True,
    }
    delete_verified = module["delete_verified"]
    delete_verified.__globals__["complete_operation"] = lambda *_args: pytest.fail(
        "completed receipt must not be updated twice"
    )

    delete_verified(operation, tmp_path, pwd.getpwuid(os.geteuid()), "unused")


def test_present_file_is_revalidated_before_claim_and_unlink(tmp_path: Path) -> None:
    module = _module()
    case_key = "case-1"
    evidence = tmp_path / case_key / "evidence"
    evidence.mkdir(parents=True)
    target = evidence / "pending.bin"
    target.write_bytes(b"pending")
    info = target.stat()
    operation = {
        "operation_id": "33333333-3333-3333-3333-333333333333",
        "runner_instance_id": "process:test",
        "prepared_facts_sha256": "sha256:" + "a" * 64,
        "receipt_claimed": False,
        "receipt_completed": False,
        "receipt_runner_instance_id": None,
        "case_key": case_key,
        "name": target.name,
        "sha256": "sha256:" + hashlib.sha256(b"pending").hexdigest(),
        "bytes": len(b"pending"),
        "st_dev": info.st_dev,
        "st_ino": info.st_ino,
        "st_nlink": 1,
    }
    calls: list[str] = []
    delete_verified = module["delete_verified"]
    delete_verified.__globals__["_immutable"] = lambda _fd: False
    delete_verified.__globals__["claim_operation"] = lambda _dsn, _op: calls.append("claim")
    delete_verified.__globals__["complete_operation"] = lambda _dsn, _op: calls.append("complete")

    delete_verified(operation, tmp_path, pwd.getpwuid(os.geteuid()), "unused")

    assert calls == ["claim", "complete"]
    assert not target.exists()
