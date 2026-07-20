"""P4.23 CP3 custody sweep — coherent absence suite (fail-on-revert).

One suite proving the deferred-deletion sweep stays deleted across every layer
the sweep touched: installer/AppArmor, the superseded gateway custody engine, the
Portal/backend recovery routes, the gateway admission short-circuits, and the
sift-core external-storage machinery. It also carries POSITIVE survivor guards so
the local-immutable admission helpers are never over-deleted with the external
scope.

Authority: ``docs/architecture/EVIDENCE-CUSTODY-SPEC.md`` (Out of Scope: external/
by-reference storage, Delete Stray, custody-delete broker, same-object Replace/
Reacquire, Exact Restore, signing rotation) and repo-root ``DELETION-MANIFEST-
CP2A.md`` §4. All checks are cheap and DB-free EXCEPT the two DB-authority tests,
which are ``integration``-marked and DSN-gated (CI Postgres + the CP3 VM gate run
them; locally they skip).
"""

from __future__ import annotations

import ast
import importlib
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parents[1]
_PACKAGES = _REPO_ROOT / "packages"
_GATEWAY_SRC = _PACKAGES / "sift-gateway" / "src" / "sift_gateway"
_CORE_SRC = _PACKAGES / "sift-core" / "src" / "sift_core"
_DASHBOARD_SRC = _PACKAGES / "case-dashboard" / "src" / "case_dashboard"

# The five concrete files the sweep deletes (DELETION-MANIFEST §2/§3 + the
# root-added signing-authority setup script + the gateway custody engine).
_DELETED_FILES = (
    _REPO_ROOT / "scripts" / "setup-custody-delete-broker.sh",
    _REPO_ROOT / "scripts" / "sift-custody-delete-broker",
    _REPO_ROOT / "configs" / "apparmor" / "sift-custody-delete-broker.template",
    _REPO_ROOT / "scripts" / "setup-custody-signing-authority.sh",
    _GATEWAY_SRC / "custody_operations.py",
)


# ---------------------------------------------------------------------------
# 1. Deleted files stay deleted; the custody engine module is unimportable
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("path", _DELETED_FILES, ids=lambda p: p.name)
def test_deleted_custody_files_are_absent(path: Path) -> None:
    assert not path.exists(), f"{path} must stay deleted (CP3 custody sweep)"


def test_custody_operations_module_is_unimportable() -> None:
    # CP2B moved portal_services off the engine, so the file is deletable outright
    # (no import-compat tombstone). A reintroduced import must fail here.
    with pytest.raises(ModuleNotFoundError):
        importlib.import_module("sift_gateway.custody_operations")


def test_no_stale_import_of_custody_operations_anywhere() -> None:
    # Fail-on-revert AST scan (imports only — a docstring mentioning the name is
    # never a false positive) matching pytest's CI collection scope
    # (testpaths = ["tests", "packages"]).
    search_roots = (_PACKAGES, _REPO_ROOT / "tests")
    hits: list[tuple[str, str]] = []
    for root in search_roots:
        if not root.exists():
            continue
        for py in root.rglob("*.py"):
            try:
                tree = ast.parse(py.read_text())
            except SyntaxError:
                continue
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        if alias.name.rsplit(".", 1)[-1] == "custody_operations":
                            hits.append((str(py), alias.name))
                elif isinstance(node, ast.ImportFrom) and node.module:
                    if node.module.rsplit(".", 1)[-1] == "custody_operations":
                        hits.append((str(py), node.module))
                    elif node.module.rsplit(".", 1)[-1] == "sift_gateway":
                        for alias in node.names:
                            if alias.name == "custody_operations":
                                hits.append((str(py), f"{node.module}.{alias.name}"))
    assert hits == []


# ---------------------------------------------------------------------------
# 2. Installer / AppArmor scrub — broker + signing-authority provisioning
# ---------------------------------------------------------------------------
def _read(path: Path) -> str:
    return path.read_text()


def test_install_sh_has_no_broker_or_signing_provisioning() -> None:
    text = _read(_REPO_ROOT / "install.sh")
    for forbidden in (
        "configure_custody_delete_broker",
        "provision_custody_delete_broker",
        "provision_custody_signing_authority",
        "setup-custody-signing-authority",
        "setup-custody-delete-broker",
    ):
        assert forbidden not in text, f"install.sh must not reference {forbidden}"


def test_migrations_sh_has_no_broker_role_or_receipts_table() -> None:
    text = _read(_REPO_ROOT / "lib" / "migrations.sh")
    for forbidden in (
        "provision_custody_delete_broker",
        "_custody_delete_broker_scope_valid",
        "custody_delete_broker_receipts",
        "sift_custody_delete_broker",
    ):
        assert forbidden not in text, f"lib/migrations.sh must not reference {forbidden}"


def test_hardening_sh_has_no_broker_apparmor_or_signing_wiring() -> None:
    text = _read(_REPO_ROOT / "lib" / "hardening.sh")
    for forbidden in (
        "sift-custody-delete-broker",
        "configure_custody_delete_broker",
        "provision_custody_signing_authority",
    ):
        assert forbidden not in text, f"lib/hardening.sh must not reference {forbidden}"


def test_uninstall_sh_has_no_ln_broker_cleanup() -> None:
    # The unrelated `ln`-aliased broker alias (a DIFFERENT, earlier helper
    # generation than sift-custody-delete-broker; see CP2A DELETION-MANIFEST
    # §2) never existed on this branch and must never reappear. This is
    # distinct from sift-custody-delete-broker itself, whose legacy teardown
    # coverage is intentionally REQUIRED — see
    # test_uninstall_sh_covers_legacy_delete_broker_and_mount_observer_teardown
    # below (CP3.5 residue repair).
    text = _read(_REPO_ROOT / "scripts" / "uninstall.sh")
    for forbidden in (
        "/etc/apparmor.d/ln",
        "/etc/sudoers.d/ln",
        "/usr/local/sbin/ln",
    ):
        assert forbidden not in text, f"scripts/uninstall.sh must not reference {forbidden}"


def test_uninstall_sh_covers_legacy_delete_broker_and_mount_observer_teardown() -> None:
    # CP3.5 residue repair: after a CP3 fast reset + exact-source reinstall,
    # these privileged artifacts from an OLDER deployment generation survived
    # because the CP3 sweep deleted their teardown lines instead of keeping
    # them as legacy-only cleanup. The uninstaller must unload/remove every
    # one of them even though current source never (re)installs them.
    text = _read(_REPO_ROOT / "scripts" / "uninstall.sh")

    apparmor = text.split("teardown_apparmor()", 1)[1].split("\n}", 1)[0]
    assert "/etc/apparmor.d/sift-custody-delete-broker" in apparmor
    assert "/etc/apparmor.d/sift-mount-observer" in apparmor
    # Both legacy profiles go through the same unload-then-remove branch as
    # the live sift-gateway/dfir-exec profiles (apparmor_parser -R before rm).
    assert "apparmor_parser -R" in apparmor

    systemd_and_users = text.split("teardown_systemd_and_users()", 1)[1].split(
        "\nteardown_fuse_conf", 1
    )[0]
    assert "sift-mount-observer.service" in systemd_and_users
    assert "/etc/sudoers.d/sift-custody-delete-broker" in systemd_and_users
    assert "/usr/local/sbin/sift-custody-delete-broker" in systemd_and_users
    assert "/etc/sift/custody-delete.json" in systemd_and_users
    assert "/etc/sift/custody-delete-dsn" in systemd_and_users


def test_uninstall_sh_stops_and_disables_legacy_mount_observer_before_removal() -> None:
    # CP3.5-R2: on a pre-CP1 VM, sift-mount-observer.service may still be
    # enabled/running. If teardown removes its unit file/AppArmor profile
    # without stopping it first, the process can survive the wipe and a
    # stale multi-user.target.wants symlink can remain. stop_sift_services
    # must stop + disable it, and must run before both removal steps.
    text = _read(_REPO_ROOT / "scripts" / "uninstall.sh")

    stop_block = text.split("stop_sift_services() {", 1)[1].split("\n}", 1)[0]
    assert "systemctl stop sift-mount-observer.service" in stop_block
    assert "systemctl disable sift-mount-observer.service" in stop_block

    main = text.split("\nmain() {", 1)[1]
    assert main.index("stop_sift_services") < main.index("teardown_apparmor")
    assert main.index("stop_sift_services") < main.index("teardown_systemd_and_users")


def test_production_install_hardening_migrations_have_no_legacy_custody_wiring() -> None:
    # The other side of the CP3.5 repair: legacy delete-broker/mount-observer
    # names are permitted ONLY in uninstall.sh teardown (proved above) and in
    # tests/comments — never in anything that installs, provisions, or wires
    # them back into a running system.
    for rel_path, forbidden_names in (
        (
            "install.sh",
            ("configure_custody_delete_broker", "sift-mount-observer"),
        ),
        (
            "lib/hardening.sh",
            (
                "sift-custody-delete-broker",
                "configure_custody_delete_broker",
                "sift-mount-observer",
            ),
        ),
        (
            "lib/migrations.sh",
            (
                "provision_custody_delete_broker",
                "custody_delete_broker_receipts",
                "sift_custody_delete_broker",
            ),
        ),
        ("lib/services.sh", ("sift-mount-observer",)),
    ):
        path = _REPO_ROOT / rel_path
        text = _read(path)
        for forbidden in forbidden_names:
            assert forbidden not in text, f"{rel_path} must not reference {forbidden}"


def test_gateway_apparmor_profile_has_no_broker_transition_or_signing_key() -> None:
    text = _read(_REPO_ROOT / "configs" / "apparmor" / "sift-gateway.template")
    # No px transition into the deleted broker, and no read grant on the
    # SPEC-out-of-scope installation-held Ed25519 signing key.
    assert "sift-custody-delete-broker" not in text
    assert "/etc/sift/custody/ed25519-private.pem" not in text


# ---------------------------------------------------------------------------
# 3. Removed Portal/backend routes + handlers (Delete Stray, Replace/Reacquire,
#    Exact Restore recovery, storage-profile change, signing-key rotation)
# ---------------------------------------------------------------------------
_REMOVED_ROUTE_PATHS = (
    "/api/evidence/chain/delete",
    "/api/evidence/chain/replace/begin",
    "/api/evidence/chain/restore/begin",
    "/api/evidence/chain/recovery/complete",
    "/api/evidence/storage/profile",
    "/api/evidence/chain/signing-key/rotate",
)
_REMOVED_ROUTE_HANDLERS = (
    "post_evidence_chain_delete",
    "post_evidence_replace_begin",
    "post_evidence_restore_begin",
    "post_evidence_recovery_complete",
    "_post_evidence_recovery_begin",
    "post_evidence_storage_profile",
    "post_evidence_chain_signing_key_rotate",
)


def test_case_dashboard_routes_removed_paths_and_handlers_are_absent() -> None:
    text = _read(_DASHBOARD_SRC / "routes.py")
    for path in _REMOVED_ROUTE_PATHS:
        assert path not in text, f"routes.py must not register {path}"
    for handler in _REMOVED_ROUTE_HANDLERS:
        assert handler not in text, f"routes.py must not define {handler}"
    # The external storage profile value must not survive in Add&Seal / status
    # validation.
    assert "EXTERNALLY_READ_ONLY" not in text


def test_portal_services_has_no_change_storage_profile() -> None:
    text = _read(_GATEWAY_SRC / "portal_services.py")
    assert "change_storage_profile" not in text
    assert "EXTERNALLY_READ_ONLY" not in text


# ---------------------------------------------------------------------------
# 4. A5 admission short-circuits removed (single admission authority = the
#    evidence-gate middleware, not a per-service resolver fallback)
# ---------------------------------------------------------------------------
def test_gateway_admission_short_circuits_are_absent() -> None:
    # The dead compatibility fallback was a per-service ``resolve_evidence_reference``
    # call that resolved (or errored on) an evidence reference OUTSIDE the single
    # admission chokepoint. Its removal is proven by the absence of that resolver
    # call in both surfaces. NOTE: the ``_evidence_ref_error`` / ``_resolved_
    # evidence_refs`` NAMES legitimately survive in mcp_server.py as ``prepared.pop``
    # strip constants — a client must never be able to inject those private fields,
    # so stripping them is desired hardening, not the removed fallback.
    for name in ("mcp_server.py", "job_tools.py"):
        text = _read(_GATEWAY_SRC / name)
        assert "resolve_evidence_reference" not in text, (
            f"{name} must not carry the dead per-service resolver short-circuit"
        )
    # Belt-and-braces: the fallback ASSIGNED the error field; the surviving code
    # only ever pops it. Assert no assignment form remains in either surface.
    for name in ("mcp_server.py", "job_tools.py"):
        text = _read(_GATEWAY_SRC / name)
        assert 'prepared["_evidence_ref_error"]' not in text
        assert "prepared[_INTERNAL_EVIDENCE_REF_ERROR] =" not in text


# ---------------------------------------------------------------------------
# 5. sift-core external-storage machinery removed
# ---------------------------------------------------------------------------
_EXTERNAL_STORAGE_NAMES = (
    "external_storage_facts",
    "ExternalReadOnlyStorage",
    "ExternalStorageFacts",
    "host_mount_observation",
    "_request_host_mount_observation",
    "HostMountObservation",
    "mount_for_fd",
    "StorageAuthorityError",
)


def test_storage_profile_has_no_external_value() -> None:
    from sift_core.evidence_storage import StorageProfile

    assert getattr(StorageProfile, "EXTERNALLY_READ_ONLY", None) is None


def test_external_storage_symbols_are_unimportable() -> None:
    import sift_core.evidence_storage as es

    present = [name for name in _EXTERNAL_STORAGE_NAMES if hasattr(es, name)]
    assert present == [], f"external-storage symbols must be gone: {present}"


def test_core_execute_has_no_external_read_only_branch() -> None:
    for name in ("evidence_binding.py", "run_command_job.py"):
        text = _read(_CORE_SRC / "execute" / name)
        assert "EXTERNALLY_READ_ONLY" not in text, (
            f"{name} must not carry an EXTERNALLY_READ_ONLY branch"
        )


# ---------------------------------------------------------------------------
# 6. SURVIVOR GUARDS — the local-immutable admission core must NOT be
#    over-deleted with the external scope.
# ---------------------------------------------------------------------------
def test_survivor_local_immutable_storage_profile() -> None:
    from sift_core.evidence_storage import StorageProfile

    assert StorageProfile.LOCAL_IMMUTABLE == "LOCAL_IMMUTABLE"


def test_survivor_local_admission_helpers_still_import() -> None:
    from sift_core.execute.evidence_binding import (
        AdmittedEvidenceBinding,
        classify_inventory_entries,
        validate_binding_fd,
    )

    assert callable(classify_inventory_entries)
    assert callable(validate_binding_fd)
    # AdmittedEvidenceBinding is the pinned local-immutable descriptor binding —
    # its import must resolve (survivor), so reference it explicitly.
    assert AdmittedEvidenceBinding.__name__ == "AdmittedEvidenceBinding"


def test_survivor_admission_still_uses_classify_inventory_entries() -> None:
    # custody/admission.py (the CP1 local reconcile/pin path) must keep importing
    # the survived helper — a regression that drops it would silently break the
    # local admission chokepoint.
    text = _read(_GATEWAY_SRC / "custody" / "admission.py")
    assert "classify_inventory_entries" in text


def test_survivor_evidence_authority_storage_execution_authority() -> None:
    # storage_execution_authority is the LIVE durable-execution authority path —
    # KEPT while its external siblings were removed.
    from sift_gateway.portal_services import EvidenceAuthorityService

    assert hasattr(EvidenceAuthorityService, "storage_execution_authority")


# ---------------------------------------------------------------------------
# 7. DB authority — broker role/table absent on a fresh migrated control plane.
#    CP1 already deleted migration 202607145200; a surviving provisioning call
#    was a fresh-install breaker. DSN-gated + integration-marked (CI Postgres /
#    CP3 VM gate run it; local `-m "not integration"` skips it).
# ---------------------------------------------------------------------------
def _dsn_or_skip() -> str:
    import os

    dsn = (os.environ.get("SIFT_CONTROL_PLANE_DSN") or "").strip()
    if not dsn:
        pytest.skip("SIFT_CONTROL_PLANE_DSN required for the CP3 DB-absence check")
    return dsn


@pytest.mark.integration
def test_broker_db_role_is_absent_on_fresh_control_plane() -> None:
    dsn = _dsn_or_skip()
    import psycopg

    with psycopg.connect(dsn) as conn, conn.cursor() as cur:
        cur.execute(
            "select 1 from pg_roles where rolname = %s",
            ("sift_custody_delete_broker",),
        )
        assert cur.fetchone() is None, (
            "sift_custody_delete_broker role must not exist on a fresh migrated DB"
        )


@pytest.mark.integration
def test_broker_receipts_table_is_absent_on_fresh_control_plane() -> None:
    dsn = _dsn_or_skip()
    import psycopg

    with psycopg.connect(dsn) as conn, conn.cursor() as cur:
        cur.execute("select to_regclass('app.custody_delete_broker_receipts')")
        row = cur.fetchone()
        assert row is not None and row[0] is None, (
            "app.custody_delete_broker_receipts must not exist on a fresh migrated DB"
        )
