"""Fail-on-revert contract for the pathless custody-delete broker."""

from __future__ import annotations

import hashlib
import json
import os
import pwd
import runpy
from pathlib import Path

import pytest
from _installer_support import REPO_ROOT

HELPER = REPO_ROOT / "scripts" / "sift-custody-delete-broker"
SETUP = REPO_ROOT / "scripts" / "setup-custody-delete-broker.sh"
INSTALLER = REPO_ROOT / "install.sh"
HARDENING = REPO_ROOT / "lib" / "hardening.sh"
UNINSTALLER = REPO_ROOT / "scripts" / "uninstall.sh"
GATEWAY_PROFILE = REPO_ROOT / "configs" / "apparmor" / "sift-gateway.template"
BROKER_PROFILE = REPO_ROOT / "configs" / "apparmor" / "sift-custody-delete-broker.template"
MIGRATION = REPO_ROOT / "supabase" / "migrations" / "202607145200_custody_delete_broker_receipts.sql"


def _module() -> dict:
    return runpy.run_path(str(HELPER))


def test_interface_is_pathless_and_profile_bound() -> None:
    source = HELPER.read_text(encoding="utf-8")
    setup = SETUP.read_text(encoding="utf-8")
    installer = INSTALLER.read_text(encoding="utf-8")
    hardening = HARDENING.read_text(encoding="utf-8")
    uninstaller = UNINSTALLER.read_text(encoding="utf-8")
    gateway = GATEWAY_PROFILE.read_text(encoding="utf-8")
    broker = BROKER_PROFILE.read_text(encoding="utf-8")

    assert 'REQUEST_KEYS = {"schema_version", "operation_id", "runner_instance_id"}' in source
    assert 'EXPECTED_PROFILE = "sift-custody-delete-broker (enforce)"' in source
    assert "shell=True" not in source
    assert "sudoers" not in setup.lower()
    assert "install -o root -g root -m 0755" in setup
    assert "sift-custody-delete-broker px -> sift-custody-delete-broker" in gateway
    assert "deny /cases/*/evidence/**                  w," in gateway
    assert "deny capability dac_override," in broker
    assert "deny capability dac_read_search," in broker
    assert "deny /bin/sh" in broker
    assert "configure_custody_delete_broker" in hardening
    assert installer.index("configure_custody_delete_broker") < installer.index("configure_apparmor")
    for installed_path in (
        "/usr/local/sbin/sift-custody-delete-broker",
        "/etc/sift/custody-delete.json",
        "/etc/apparmor.d/sift-custody-delete-broker",
    ):
        assert installed_path in uninstaller


def test_broker_rebinds_uuid_to_postgres_and_durable_receipt() -> None:
    source = HELPER.read_text(encoding="utf-8")
    migration = MIGRATION.read_text(encoding="utf-8")

    for binding in (
        'action != "DELETE_STRAY"',
        'phase != "FILESYSTEM_APPLYING"',
        'command.get("schema_version") != 2',
        'storage_profile != "LOCAL_IMMUTABLE"',
        'storage_state != "AVAILABLE"',
        "obj.id::text=op.command->>'evidence_object_id'",
        "prepared_facts_sha256",
        "missing_without_broker_claim",
        "os.O_NOFOLLOW",
        "regular_single_link_required",
        "immutable_evidence_refused",
        "os.fsync(evidence_fd)",
    ):
        assert binding in source
    assert "create table app.custody_delete_broker_receipts" in migration
    assert "force row level security" in migration
    assert "revoke all" in migration


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
