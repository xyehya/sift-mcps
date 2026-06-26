"""#18 (I-PS4): install.sh is a thin entrypoint that sources lib/*.sh.

FAIL-ON-REVERT guards for the modularization. These pin the contract that:

* install.sh stays a THIN entrypoint (it must not regrow back into a monolith);
* the lib/*.sh modules exist, are source-guarded, and are side-effect-free on
  source (no install step runs merely from `source`);
* the BASH_SOURCE direct-exec guard is intact, so `source install.sh` (as
  scripts/setup-addon.sh:87 does) exposes every provisioning function WITHOUT
  kicking off an install;
* the functions carried verbatim from #17/#11 (uv SHA-pin, zimmerman,
  complementary tools) and the OpenCTI add-on helpers consumed by
  scripts/setup-addon.sh are still defined after sourcing;
* the verified-dead no-op ``fix_volatility_permissions`` is gone;
* an extracted lib function (``verify_sha256`` — the #17 supply-chain gate) runs
  correctly when reached through the modular sourcing path.
"""

from __future__ import annotations

import hashlib
import os
import subprocess
from pathlib import Path

import pytest
from _installer_support import INSTALL_SH, LIB_DIR, REPO_ROOT
from _installer_support import run_bash as _run_bash

# Functions that MUST remain available after `source install.sh`. Mix of #17/#11
# carry-overs, the OpenCTI add-on helpers (consumed by setup-addon.sh), and one
# function from every lib module so a dropped/renamed module is caught.
REQUIRED_FUNCS = (
    # common.sh / early helpers + staging
    "verify_sha256",
    "stage_repo_to_install_root",
    # preflight.sh
    "check_os",
    "install_host_prereqs",
    # python.sh — #17 uv SHA-pin carry-over
    "install_uv_if_needed",
    "sync_workspace",
    # state.sh
    "install_state_dirs",
    # assets.sh — #11 carry-overs
    "install_zimmerman_symlinks",
    "install_complementary_tools",
    "install_hayabusa",
    # tls.sh
    "generate_tls",
    # examiner.sh
    "write_default_examiner",
    "seed_addon_backends",
    # supabase.sh
    "write_control_plane_env",
    # migrations.sh
    "apply_db_migrations",
    "provision_audit_writer",
    # config.sh
    "write_gateway_config",
    # opensearch.sh
    "start_opensearch",
    # addons.sh — OpenCTI helpers consumed by scripts/setup-addon.sh:643
    "prepare_opencti_secrets",
    "install_opencti",
    "install_opencti_feeds",
    # services.sh
    "install_systemd_service",
    "poll_gateway",
    # handoff.sh
    "write_handoff",
    "print_summary",
    # hardening.sh
    "configure_apparmor",
    # teardown.sh
    "do_uninstall",
    # the orchestrator itself
    "main",
)


# ---------------------------------------------------------------------------
# Structure: install.sh is thin; lib/ exists and is guarded
# ---------------------------------------------------------------------------
def test_install_sh_is_thin_entrypoint() -> None:
    """The monolith (3.8k lines) must stay decomposed. A generous ceiling still
    fails loudly if the logic is pulled back into install.sh."""
    n = INSTALL_SH.read_text(encoding="utf-8").count("\n")
    assert n < 500, f"install.sh has {n} lines — it should be a thin entrypoint (<500); did the monolith regrow?"


def test_lib_dir_has_modules() -> None:
    mods = sorted(p.stem for p in LIB_DIR.glob("*.sh"))
    assert "common" in mods, "lib/common.sh (globals + early helpers) is required and sourced first."
    assert len(mods) >= 10, f"expected the installer split across many modules; found only {mods}"


def test_entrypoint_sources_lib_and_guards_main() -> None:
    src = INSTALL_SH.read_text(encoding="utf-8")
    assert "lib" in src and "source" in src, "entrypoint must source the lib/*.sh modules."
    # The direct-exec guard: main runs only when executed directly, not on source.
    assert '"${BASH_SOURCE[0]}" == "${0}"' in src, "the direct-exec main() guard must be preserved."


@pytest.mark.parametrize("mod", sorted(p for p in LIB_DIR.glob("*.sh")))
def test_lib_modules_are_source_guarded(mod: Path) -> None:
    """Every lib module must carry a re-source guard so double-sourcing is a
    no-op (idempotent sourcing)."""
    text = mod.read_text(encoding="utf-8")
    assert "_SIFT_LIB_" in text and "_SOURCED" in text, f"{mod.name} lacks its source guard."


# ---------------------------------------------------------------------------
# Sourcing contract: functions available, NO install runs (mirrors setup-addon)
# ---------------------------------------------------------------------------
def test_sourcing_exposes_functions_without_install() -> None:
    """`source install.sh` must define every provisioning function and resolve
    REPO_DIR WITHOUT running an install — exactly how scripts/setup-addon.sh
    consumes it. A tripwire on the first install step (stage_repo_to_install_root)
    catches any accidental top-level invocation."""
    funcs = " ".join(REQUIRED_FUNCS)
    script = f"""
set -Eeuo pipefail
# Tripwire: if sourcing ever runs an install step, this aborts non-zero.
stage_repo_to_install_root() {{ echo "INSTALL_RAN_ON_SOURCE" >&2; exit 99; }}
source ./install.sh
for fn in {funcs}; do
  if ! type "$fn" >/dev/null 2>&1; then
    echo "MISSING_FUNC:$fn" >&2
    exit 1
  fi
done
# REPO_DIR must resolve to the repo root (where install.sh lives), not lib/.
[[ "$REPO_DIR" == "$(pwd -P)" ]] || {{ echo "BAD_REPO_DIR:$REPO_DIR" >&2; exit 2; }}
echo "OK_FUNCS_AVAILABLE"
"""
    res = _run_bash(script)
    assert "INSTALL_RAN_ON_SOURCE" not in res.stderr, "sourcing install.sh kicked off an install — guard broken."
    assert res.returncode == 0, f"sourcing contract failed:\n{res.stdout}\n{res.stderr}"
    assert "OK_FUNCS_AVAILABLE" in res.stdout


def test_dead_no_op_function_removed() -> None:
    """fix_volatility_permissions was a verified no-op (return 0) called once in
    main(); #18 removed the function AND its call site. It must not reappear."""
    script = """
set -Eeuo pipefail
source ./install.sh
if type fix_volatility_permissions >/dev/null 2>&1; then
  echo "DEAD_FUNC_PRESENT" >&2; exit 1
fi
echo "DEAD_FUNC_GONE"
"""
    res = _run_bash(script)
    assert res.returncode == 0, f"dead no-op fix_volatility_permissions still present:\n{res.stderr}"
    assert "DEAD_FUNC_GONE" in res.stdout
    # And no lingering call site anywhere in the installer source.
    blob = INSTALL_SH.read_text(encoding="utf-8")
    blob += "\n".join(p.read_text(encoding="utf-8") for p in LIB_DIR.glob("*.sh"))
    assert "fix_volatility_permissions" not in blob, "fix_volatility_permissions reference still in installer source."


# ---------------------------------------------------------------------------
# An extracted lib function actually works through the modular path
# ---------------------------------------------------------------------------
def test_extracted_verify_sha256_runs_via_modular_path(tmp_path: Path) -> None:
    """Drive the #17 supply-chain gate (verify_sha256, now in lib/common.sh)
    through `source install.sh`: a matching hash returns 0, a tampered one
    returns non-zero. Proves the extracted function is reachable and intact."""
    sample = tmp_path / "artifact.bin"
    sample.write_bytes(b"sift-mcps modular installer test artifact")
    good = hashlib.sha256(sample.read_bytes()).hexdigest()
    bad = "0" * 64

    script_ok = f"""
set -uo pipefail
source ./install.sh
verify_sha256 "{sample}" "{good}"; echo "RC=$?"
"""
    res_ok = _run_bash(script_ok)
    assert "RC=0" in res_ok.stdout, f"verify_sha256 rejected a MATCHING hash:\n{res_ok.stdout}\n{res_ok.stderr}"

    # install.sh sets `set -e` on source, so guard the expected-failure call with
    # an `if` (a non-zero return inside an `if` condition does NOT trip `set -e`).
    script_bad = f"""
source ./install.sh
if verify_sha256 "{sample}" "{bad}"; then echo "RC=0"; else echo "RC=1"; fi
"""
    res_bad = _run_bash(script_bad)
    assert "RC=0" not in res_bad.stdout, "verify_sha256 ACCEPTED a tampered hash — the #17 gate is broken."
    assert "RC=1" in res_bad.stdout


def test_help_output_unchanged_marker() -> None:
    """`./install.sh --help` must still run end-to-end (exit 0) through the
    modular entrypoint and print the usage banner — the operator-facing UX."""
    res = subprocess.run(
        ["bash", str(INSTALL_SH), "--help"],
        cwd=str(REPO_ROOT),
        capture_output=True,
        text=True,
        env={"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": os.environ.get("HOME", "/tmp")},
    )
    assert res.returncode == 0, f"--help failed through the modular entrypoint:\n{res.stderr}"
    assert "Usage: ./install.sh [OPTIONS]" in res.stdout
    assert "--core-only" in res.stdout and "--uninstall" in res.stdout
