"""Fail-on-revert contract for the greenfield uninstaller."""

from __future__ import annotations

import subprocess
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
UNINSTALL_SH = REPO_ROOT / "scripts" / "uninstall.sh"
TEARDOWN_SH = REPO_ROOT / "lib" / "teardown.sh"
COMMON_SH = REPO_ROOT / "lib" / "common.sh"


def test_uninstall_sh_exists_and_parses() -> None:
    assert UNINSTALL_SH.is_file()
    res = subprocess.run(
        ["bash", "-n", str(UNINSTALL_SH)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert res.returncode == 0, res.stderr


def test_greenfield_default_does_not_purge_cases_without_data_flag() -> None:
    src = UNINSTALL_SH.read_text(encoding="utf-8")
    # Evidence purge is gated behind PURGE_DATA / --data.
    assert 'if [[ "$PURGE_DATA" -eq 1 ]]' in src
    assert "--data" in src
    # Default path must not call _purge_tree on cases outside confirm_evidence_removal.
    confirm = src.split("confirm_evidence_removal()", 1)[1].split("\n}", 1)[0]
    assert "_purge_tree \"$SIFT_CASES_ROOT\"" in confirm
    main = src.split("main()", 1)[1]
    # main only reaches evidence teardown when PURGE_DATA is set.
    assert 'if [[ "$PURGE_DATA" -eq 1 ]]' in main
    assert "confirm_evidence_removal" in main


def test_evidence_still_triple_gated() -> None:
    src = UNINSTALL_SH.read_text(encoding="utf-8")
    assert "confirm_evidence_removal" in src
    assert "--i-understand-evidence-loss" in src
    assert "DELETE EVIDENCE" in src
    assert "SIFT_PURGE_DATA" in src
    assert "SIFT_PURGE_EVIDENCE_ACK" in src


def test_keep_caches_preserves_durable_tree_and_skips_image_rm() -> None:
    src = UNINSTALL_SH.read_text(encoding="utf-8")
    assert "--keep-caches" in src
    assert "SIFT_KEEP_CACHES" in src
    assert "/var/cache/sift" in src
    assert "SIFT_UV_CACHE_DIR" in src
    assert "SIFT_HF_HOME" in src
    assert "SIFT_WINDOWS_TRIAGE_DATA_DIR" in src

    preserve = src.split("teardown_or_preserve_caches()", 1)[1].split("\n}", 1)[0]
    assert 'KEEP_CACHES" -eq 1' in preserve
    assert "Preserving durable caches" in preserve

    images = src.split("teardown_docker_images()", 1)[1].split("\n}", 1)[0]
    assert 'KEEP_CACHES" -eq 1' in images
    assert "Keeping Docker images" in images
    # Image removal lives in this function and is skipped when keep-caches is on.
    assert "docker image rm" in images


def test_without_keep_caches_cache_tree_is_targeted() -> None:
    src = UNINSTALL_SH.read_text(encoding="utf-8")
    preserve = src.split("teardown_or_preserve_caches()", 1)[1].split("\n}", 1)[0]
    assert "all durable SIFT caches" in preserve
    assert 'rm -rf' in preserve and "SIFT_CACHE_ROOT" in preserve


def test_opencti_teardown_still_shared_only() -> None:
    source = UNINSTALL_SH.read_text(encoding="utf-8")
    # Compose targets live in the authoritative Docker force-purge path.
    assert "docker-compose.opencti-shared.yml" in source
    assert "docker-compose.opencti-connectors.yml" in source
    assert "docker-compose.opencti.yml" not in source
    assert "opencti-opensearch" not in source
    assert "sift-opencti-net" not in source
    secrets = source.split("teardown_opencti()", 1)[1].split("\n}", 1)[0]
    assert "opencti-query.env" in secrets
    assert "opencti-stack.env" in secrets


def test_docker_volumes_always_purged_even_with_keep_caches() -> None:
    src = UNINSTALL_SH.read_text(encoding="utf-8")
    assert "force_purge_sift_docker_state" in src
    assert "_docker_force_rm_matching_containers" in src
    assert "_docker_list_sift_volumes" in src
    assert "Named SIFT Docker volumes still present" in src
    # -q + --format drops names; force-rm must list ID and Names.
    assert "docker ps -a --format '{{.ID}} {{.Names}}'" in src
    assert "docker ps -aq --format" not in src
    # keep-caches only skips image rm — volumes still verified gone.
    images = src.split("teardown_docker_images()", 1)[1].split("\n}", 1)[0]
    assert 'KEEP_CACHES" -eq 1' in images
    assert "Named volumes were still purged" in images
    # Services stop before Docker so volumes are not held open.
    main = src.split("main()", 1)[1]
    assert main.index("stop_sift_services") < main.index("force_purge_sift_docker_state")


def test_keep_caches_does_not_spare_venv_or_volumes() -> None:
    src = UNINSTALL_SH.read_text(encoding="utf-8")
    header = "\n".join(src.splitlines()[:45])
    assert "does NOT keep volumes" in header
    runtime = src.split("teardown_runtime()", 1)[1].split("\nteardown_state", 1)[0]
    assert ".venv" in runtime
    assert "sudo_if_needed rm -rf" in runtime


def test_apparmor_teardown_includes_dfir_exec() -> None:
    src = UNINSTALL_SH.read_text(encoding="utf-8")
    section = src.split("teardown_apparmor()", 1)[1].split("\n}", 1)[0]
    assert "/etc/apparmor.d/sift-gateway" in section
    assert "/etc/apparmor.d/dfir-exec" in section
    assert "/etc/apparmor.d/sift-custody-delete-broker" in section


def test_addon_sandbox_sudoers_removed() -> None:
    src = UNINSTALL_SH.read_text(encoding="utf-8")
    assert "sift-addon-systemd-sandbox" in src


def test_durable_cache_defaults_in_common() -> None:
    src = COMMON_SH.read_text(encoding="utf-8")
    assert 'SIFT_CACHE_ROOT="${SIFT_CACHE_ROOT:-/var/cache/sift}"' in src
    assert 'SIFT_HF_HOME="${SIFT_HF_HOME:-$SIFT_CACHE_ROOT/huggingface}"' in src
    assert 'SIFT_UV_CACHE_DIR="${SIFT_UV_CACHE_DIR:-$SIFT_CACHE_ROOT/uv}"' in src
    assert "SIFT_WINDOWS_TRIAGE_DATA_DIR" in src
    # Old state-dir HF default must not remain the primary default.
    assert 'SIFT_HF_HOME="${SIFT_HF_HOME:-$SIFT_STATE_DIR/.cache/huggingface}"' not in src


def test_install_shim_never_forwards_data_flags() -> None:
    teardown = TEARDOWN_SH.read_text(encoding="utf-8")
    body = teardown.split("do_uninstall()", 1)[1].split("\n}", 1)[0]
    assert "scripts/uninstall.sh" in body
    assert "local args=(--i-understand)" in body
    assert "args+=(--data)" not in body
    assert "args+=(--i-understand-evidence-loss)" not in body
    assert "args+=(--remove-evidence)" not in body
    assert "--remove-evidence" not in body
    # keep-caches may be forwarded from env — that is intentional and not evidence.
    assert "SIFT_KEEP_CACHES" in body


def test_component_menu_options_removed() -> None:
    src = UNINSTALL_SH.read_text(encoding="utf-8")
    help_out = subprocess.run(
        ["bash", str(UNINSTALL_SH), "--help"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert help_out.returncode == 0
    assert "--keep-caches" in help_out.stdout
    assert "--data" in help_out.stdout
    # Old interactive component menu is gone.
    assert "Select components to remove" not in src
    res = subprocess.run(
        ["bash", str(UNINSTALL_SH), "--components", "opencti"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert res.returncode != 0
    assert "removed" in res.stderr.lower() or "FATAL" in res.stderr
