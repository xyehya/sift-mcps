"""G-9 / D5 (#16): the installer must have NO code path that can delete case evidence.

Immutability boundary #2 (sift-architecture.html): evidence under ``/cases`` is
append-only and physically immutable (``chattr +i`` / custody chain). A forensic
installer that can clear those flags and ``rm -rf`` the cases root violates that
boundary by construction — a wiped evidence root cannot be "verified" after the
fact, so the only safe invariant is that ``install.sh`` contains no such path at all.

The canonical, correctly-gated evidence teardown lives ONLY in
``scripts/uninstall.sh`` (``confirm_evidence_removal``: requires
``--remove-evidence`` + ``--i-understand-evidence-loss`` + ``--yes`` + a typed
``DELETE EVIDENCE``). ``install.sh`` must DELEGATE uninstall there and never carry
its own evidence-delete branch.

These are STATIC GUARD tests (fail-on-revert): they assert the dangerous tokens
are absent from ``install.sh`` source. They are deliberately blunt — re-introducing
the inline purge in any recognizable form trips them. A behavioral check confirms
``install.sh`` no longer accepts ``--purge-data`` and that its uninstall shim never
forwards the evidence-loss flags downstream.
"""
from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
INSTALL_SH = REPO_ROOT / "install.sh"
UNINSTALL_SH = REPO_ROOT / "scripts" / "uninstall.sh"


@pytest.fixture(scope="module")
def install_src() -> str:
    return INSTALL_SH.read_text(encoding="utf-8")


# ---------------------------------------------------------------------------
# Static guards — the dangerous evidence-delete path must not exist in install.sh
# ---------------------------------------------------------------------------
def test_install_sh_exists() -> None:
    assert INSTALL_SH.is_file(), f"{INSTALL_SH} missing"


def test_no_purge_data_flag(install_src: str) -> None:
    """``--purge-data`` is the operator-facing trigger for the /cases wipe. It must
    be gone entirely — no arg parsing, no help text, no doc mention in install.sh."""
    assert "--purge-data" not in install_src, (
        "install.sh still references --purge-data; the /cases-wiping flag must be "
        "removed entirely (delegate uninstall to scripts/uninstall.sh instead)."
    )


def test_no_purge_data_env_var(install_src: str) -> None:
    """The PURGE_DATA env toggle that drove the inline wipe must be gone too."""
    assert "PURGE_DATA" not in install_src, (
        "install.sh still references PURGE_DATA; the inline data/evidence purge "
        "toggle must be removed (uninstall is delegated to scripts/uninstall.sh)."
    )


def test_no_purge_data_functions(install_src: str) -> None:
    """The inline purge helpers must not be defined in install.sh."""
    for fn in ("_purge_tree", "purge_data"):
        assert not re.search(rf"^\s*{re.escape(fn)}\s*\(\)", install_src, re.MULTILINE), (
            f"install.sh still defines {fn}(); the inline evidence/state purge "
            "helpers must be deleted (D5: installer cannot delete evidence)."
        )
        assert fn not in install_src, (
            f"install.sh still references {fn}; it must be removed entirely."
        )


def test_no_chattr_immutable_unlock_of_cases(install_src: str) -> None:
    """Clearing chattr +i / +a is how the old purge unlocked immutable evidence
    before deleting it. The installer must never unlock the immutability flags
    (immutability boundary #2)."""
    # No `chattr ... -i` and no `chattr ... -a` anywhere in install.sh.
    bad = re.findall(r"chattr[^\n]*-[ia]\b", install_src)
    assert not bad, (
        "install.sh runs chattr to clear immutable/append-only flags "
        f"({bad!r}); unlocking evidence immutability is forbidden (D5 / boundary #2)."
    )
    assert "chattr" not in install_src, (
        "install.sh references chattr; the installer must not manipulate evidence "
        "immutability flags at all."
    )


def test_no_rm_rf_targeting_cases_root(install_src: str) -> None:
    """No ``rm -rf`` (sudo or not) may target the cases/evidence root or its var."""
    # Any rm -rf line that names the cases root variable or /cases literal.
    for m in re.finditer(r"^.*\brm\s+-rf\b.*$", install_src, re.MULTILINE):
        line = m.group(0)
        assert "SIFT_CASE_ROOT" not in line and "SIFT_CASES_ROOT" not in line, (
            f"install.sh has an rm -rf targeting the cases root: {line.strip()!r}"
        )
        assert "/cases" not in line, (
            f"install.sh has an rm -rf targeting /cases: {line.strip()!r}"
        )


def test_do_uninstall_delegates_to_canonical_script(install_src: str) -> None:
    """do_uninstall must route through scripts/uninstall.sh (the gated, canonical
    teardown), not carry its own teardown of data/evidence."""
    assert "scripts/uninstall.sh" in install_src, (
        "install.sh no longer delegates to scripts/uninstall.sh; do_uninstall must "
        "invoke the canonical, evidence-gated uninstaller."
    )


def test_do_uninstall_never_forwards_evidence_flags(install_src: str) -> None:
    """Even when delegating, install.sh must NEVER pass the evidence-loss gates
    down to scripts/uninstall.sh — those may only be supplied by an operator
    running scripts/uninstall.sh directly."""
    for flag in ("--remove-evidence", "--i-understand-evidence-loss"):
        assert flag not in install_src, (
            f"install.sh references {flag}; it must never forward evidence-removal "
            "gates to scripts/uninstall.sh."
        )


# ---------------------------------------------------------------------------
# Behavioral guard — sourcing/parsing install.sh must not expose a /cases wipe
# ---------------------------------------------------------------------------
def test_purge_data_flag_is_not_accepted() -> None:
    """`./install.sh --uninstall --purge-data -y` must NOT silently wipe evidence.
    With the flag removed, install.sh must treat --purge-data as an unknown option
    (warn + ignore) rather than triggering a purge. We assert the flag is unknown by
    confirming it appears nowhere in the parse loop's recognized cases."""
    src = INSTALL_SH.read_text(encoding="utf-8")
    # Extract the arg-parse while-loop body and assert --purge-data is not a case arm.
    assert not re.search(r"--purge-data\)\s", src), (
        "install.sh still has a --purge-data) case arm in its arg parser."
    )


def test_install_sh_syntax_ok() -> None:
    """A broken shim is worse than the bug. install.sh must parse clean."""
    res = subprocess.run(
        ["bash", "-n", str(INSTALL_SH)],
        capture_output=True,
        text=True,
    )
    assert res.returncode == 0, f"bash -n install.sh failed:\n{res.stderr}"


def test_canonical_uninstaller_still_gates_evidence() -> None:
    """Sanity: the delegation target keeps its triple gate (we must not have
    weakened it). scripts/uninstall.sh requires the evidence-loss flags + typed
    confirmation."""
    src = UNINSTALL_SH.read_text(encoding="utf-8")
    assert "confirm_evidence_removal" in src
    assert "--i-understand-evidence-loss" in src
    assert "DELETE EVIDENCE" in src
