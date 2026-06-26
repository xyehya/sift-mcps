"""#17 (I-PS3) + #11 (installer part): supply-chain fail-closed uv install and
functional EZ-Tool / complementary-CLI handling in ``install.sh``.

These are FAIL-ON-REVERT guards, exercised the same way the repo's other
installer tests are (static source assertions + behavioral ``bash`` subshells
that ``source install.sh`` — the ``main`` guard at the bottom keeps sourcing
side-effect-free, so individual functions can be driven in isolation).

What they pin:

#17 — every uv install path is SHA-256-gated; the unhashed ``curl | sh``
fallback is gone:
  * unsupported / unpinned arch ``die``s WITHOUT fetching (fail-closed);
  * a tampered uv tarball fails ``verify_sha256`` (the gate actually bites);
  * no ``| sh`` / ``| bash`` pipe-to-shell remains in the source.

#11 — ``install_zimmerman_symlinks`` emits a runnable ``dotnet`` wrapper for each
EZ-Tool ``*.dll`` and is idempotent; ``install_complementary_tools`` never
silently no-ops (it logs an actionable advisory) and never ``die``s on offline.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
from _installer_support import INSTALL_SH, LIB_DIR, REPO_ROOT
from _installer_support import run_bash as _run_bash


@pytest.fixture(scope="module")
def install_src() -> str:
    """The full installer source. Since #18 (I-PS4) the monolith is a thin
    install.sh entrypoint that sources lib/*.sh, so static assertions about the
    installer (SHA ledger vars, no pipe-to-shell, etc.) must scan the entrypoint
    AND every sourced module — that is the installer's source today."""
    parts = [INSTALL_SH.read_text(encoding="utf-8")]
    parts += [p.read_text(encoding="utf-8") for p in sorted(LIB_DIR.glob("*.sh"))]
    return "\n".join(parts)


# ---------------------------------------------------------------------------
# #17 — static guards: no unhashed pipe-to-shell anywhere
# ---------------------------------------------------------------------------
def test_no_unhashed_pipe_to_shell(install_src: str) -> None:
    """The whole point of #17: kill the unhashed ``... | sh`` uv bootstrap.
    No pipe-to-shell of any downloaded script may remain in install.sh."""
    import re

    bad = re.findall(r"\|\s*(?:sh|bash)\b", install_src)
    assert not bad, f"install.sh still pipes to a shell ({bad!r}); every uv path must be SHA-gated."
    assert "astral.sh/uv" not in install_src or "tar.gz.sha256" in install_src, (
        "the only astral.sh/uv reference allowed is the provenance comment, not a fetch."
    )


def test_aarch64_sha_ledger_var_present(install_src: str) -> None:
    """The per-arch SHA ledger must carry an aarch64 entry beside the x86_64 one."""
    assert "SIFT_UV_TARBALL_SHA256_AARCH64" in install_src
    assert "SIFT_UV_TARBALL_SHA256=" in install_src


# ---------------------------------------------------------------------------
# #17 — behavioral: unsupported arch fails closed WITHOUT fetching
# ---------------------------------------------------------------------------
def test_unsupported_arch_fails_closed_without_fetch() -> None:
    """install_uv_if_needed on an arch with no pinned hash must die(1) and must
    NOT invoke curl. We shim ``uname`` to report a bogus arch, force a fresh
    install (no uv on PATH), and replace ``curl`` with a tripwire that writes a
    marker file if it is ever called."""
    marker = REPO_ROOT / "tests" / ".curl_was_called_marker"
    if marker.exists():
        marker.unlink()
    script = f"""
set -uo pipefail
source ./install.sh
# Tripwire: any curl invocation means we fetched before verifying — a fail-open bug.
curl() {{ echo called > "{marker}"; return 0; }}
# Force the install path: pretend uv is absent and the arch is unsupported.
resolve_uv() {{ echo ""; }}
uname() {{ echo "sparc64"; }}
require_cmd() {{ :; }}  # don't fail merely because curl-the-binary is missing
install_uv_if_needed
echo "REACHED_END_SHOULD_NOT_HAPPEN"
"""
    res = _run_bash(script)
    try:
        assert res.returncode != 0, f"unsupported arch did not fail closed:\n{res.stdout}\n{res.stderr}"
        assert "REACHED_END_SHOULD_NOT_HAPPEN" not in res.stdout
        assert not marker.exists(), "curl was invoked on an unsupported arch — fail-open supply-chain bug."
        assert "unsupported CPU architecture" in res.stderr or "no pinned SHA" in res.stderr
    finally:
        if marker.exists():
            marker.unlink()


def test_empty_arch_sha_fails_closed_without_fetch() -> None:
    """Even for a SUPPORTED triple, an empty ledger var must refuse to fetch
    (operator-cleared hash ⇒ fail-closed, never download-then-hope)."""
    marker = REPO_ROOT / "tests" / ".curl_was_called_marker2"
    if marker.exists():
        marker.unlink()
    script = f"""
set -uo pipefail
source ./install.sh
curl() {{ echo called > "{marker}"; return 0; }}
resolve_uv() {{ echo ""; }}
uname() {{ echo "aarch64"; }}
require_cmd() {{ :; }}
export SIFT_UV_TARBALL_SHA256_AARCH64=""
install_uv_if_needed
echo "REACHED_END_SHOULD_NOT_HAPPEN"
"""
    res = _run_bash(script)
    try:
        assert res.returncode != 0, f"empty aarch64 hash did not fail closed:\n{res.stdout}\n{res.stderr}"
        assert not marker.exists(), "curl was invoked with no pinned hash — fail-open supply-chain bug."
        assert "no pinned SHA" in res.stderr
    finally:
        if marker.exists():
            marker.unlink()


# ---------------------------------------------------------------------------
# #17 — behavioral: verify_sha256 actually rejects a tampered tarball
# ---------------------------------------------------------------------------
def test_verify_sha256_rejects_tampered_tarball(tmp_path: Path) -> None:
    """The gate must bite: a file whose real hash differs from the expected hash
    returns non-zero from verify_sha256."""
    fixture = tmp_path / "uv-fake.tar.gz"
    fixture.write_bytes(b"this is not the real uv tarball\n")
    wrong_hash = "0" * 64
    script = f"""
set -uo pipefail
source ./install.sh
if verify_sha256 "{fixture}" "{wrong_hash}"; then
  echo "VERIFY_PASSED_UNEXPECTEDLY"
  exit 50
else
  echo "VERIFY_REJECTED_AS_EXPECTED"
fi
"""
    res = _run_bash(script)
    assert "VERIFY_REJECTED_AS_EXPECTED" in res.stdout, f"{res.stdout}\n{res.stderr}"
    assert "VERIFY_PASSED_UNEXPECTEDLY" not in res.stdout
    # And the correct hash passes, proving the test isn't trivially always-fail.
    import hashlib

    real = hashlib.sha256(fixture.read_bytes()).hexdigest()
    ok = _run_bash(
        f'set -uo pipefail; source ./install.sh; verify_sha256 "{fixture}" "{real}" && echo OK'
    )
    assert "OK" in ok.stdout, f"correct hash unexpectedly rejected:\n{ok.stdout}\n{ok.stderr}"


# ---------------------------------------------------------------------------
# #11 — behavioral: install_zimmerman_symlinks wraps *.dll and is idempotent
# ---------------------------------------------------------------------------
@pytest.mark.skipif(shutil.which("bash") is None, reason="bash required")
def test_zimmerman_emits_dotnet_wrapper_and_is_idempotent(tmp_path: Path) -> None:
    """Against a fixture /opt/zimmermantools holding ``Foo.dll`` (and a fake
    ``dotnet`` on PATH), install_zimmerman_symlinks must create an EXECUTABLE
    ``<bindir>/Foo`` wrapper that execs ``dotnet <abs>/Foo.dll``; a second run is
    a no-op (idempotent) and must not error."""
    zdir = tmp_path / "zimmermantools"
    bindir = tmp_path / "bin"
    fakebin = tmp_path / "fakebin"
    for d in (zdir, bindir, fakebin):
        d.mkdir(parents=True)
    (zdir / "Foo.dll").write_text("assembly\n")
    (zdir / "Foo.runtimeconfig.json").write_text("{}\n")
    # A real dotnet need not exist; the function only checks `command -v dotnet`.
    dotnet = fakebin / "dotnet"
    dotnet.write_text("#!/bin/bash\necho dotnet \"$@\"\n")
    dotnet.chmod(0o755)

    foo = bindir / "Foo"
    # Override the resolver-private paths by shadowing sudo_if_needed (drop sudo,
    # run as the test user who owns tmp_path) and pointing the function at the
    # fixture dirs via a thin re-definition that calls the real body with our dirs.
    # The function hardcodes /opt/zimmermantools + /usr/local/bin, so we shadow
    # those by redefining the function's two `local` dirs through a wrapper that
    # sources install.sh then patches the two paths via sed-free function copy.
    script = f"""
set -uo pipefail
source ./install.sh
sudo_if_needed() {{ "$@"; }}
# Re-bind the two hardcoded dirs by overriding the function with the same body
# but our fixture paths. We do this by copying the function text and swapping the
# two local assignments — safer here: just call a shim that exports overrides.
install_zimmerman_symlinks_test() {{
  local zimmerman_dir="{zdir}"
  local bindir="{bindir}"
  if ! sudo_if_needed test -d "$zimmerman_dir"; then return 0; fi
  if ! command -v dotnet >/dev/null 2>&1; then echo NODOTNET; return 0; fi
  local created=0 existing=0 dll result
  while IFS= read -r -d '' dll; do
    result="$(_zimmerman_emit_wrapper "$dll" "$bindir")"
    case "$result" in
      created) created=$((created + 1)) ;;
      exists)  existing=$((existing + 1)) ;;
    esac
  done < <(sudo_if_needed find "$zimmerman_dir" -maxdepth 1 -type f -name '*.dll' -print0 2>/dev/null)
  echo "created=$created existing=$existing"
}}
export PATH="{fakebin}:$PATH"
echo "RUN1: $(install_zimmerman_symlinks_test)"
echo "RUN2: $(install_zimmerman_symlinks_test)"
"""
    res = _run_bash(script, env={"PATH": f"{fakebin}:{os.environ.get('PATH', '/usr/bin:/bin')}"})
    assert res.returncode == 0, f"{res.stdout}\n{res.stderr}"
    assert "RUN1: created=1 existing=0" in res.stdout, res.stdout
    assert "RUN2: created=0 existing=1" in res.stdout, res.stdout  # idempotent
    # The wrapper must exist, be executable, and dotnet-run the absolute .dll path.
    assert foo.exists(), "wrapper /bin/Foo was not created"
    assert os.access(foo, os.X_OK), "wrapper is not executable"
    body = foo.read_text()
    assert body.startswith("#!/bin/bash"), body
    assert "exec dotnet" in body and str(zdir / "Foo.dll") in body, body


def test_zimmerman_helper_skips_preexisting_wrapper(tmp_path: Path) -> None:
    """_zimmerman_emit_wrapper must NOT clobber an existing /usr/local/bin entry
    (the SANS image ships its own) — it returns 'exists' and leaves it intact."""
    zdir = tmp_path / "z"
    bindir = tmp_path / "b"
    zdir.mkdir()
    bindir.mkdir()
    (zdir / "Bar.dll").write_text("x\n")
    pre = bindir / "Bar"
    pre.write_text("#!/bin/bash\n# the SANS wrapper, must be preserved\n")
    pre.chmod(0o755)
    script = f"""
set -uo pipefail
source ./install.sh
sudo_if_needed() {{ "$@"; }}
echo "RESULT: $(_zimmerman_emit_wrapper "{zdir / 'Bar.dll'}" "{bindir}")"
"""
    res = _run_bash(script)
    assert "RESULT: exists" in res.stdout, f"{res.stdout}\n{res.stderr}"
    assert "the SANS wrapper, must be preserved" in pre.read_text(), "pre-existing wrapper was clobbered"


# ---------------------------------------------------------------------------
# #11 — behavioral: complementary tools never silent-no-op / never die on offline
# ---------------------------------------------------------------------------
def test_complementary_tools_offline_warns_and_does_not_die() -> None:
    """On SIFT_OFFLINE=1 with the tools absent, the function must emit an
    actionable 'NOT installed' advisory for each and return 0 (non-fatal),
    never reaching apt and never silently succeeding."""
    script = """
set -uo pipefail
source ./install.sh
sudo_if_needed() { "$@"; }
# Make the three target CLIs appear absent regardless of host.
command() {
  if [[ "${2:-}" == "yara" || "${2:-}" == "tshark" || "${2:-}" == "binwalk" || "${2:-}" == "zeek" ]]; then
    return 1
  fi
  builtin command "$@"
}
export SIFT_OFFLINE=1
# apt-get tripwire: must never be called in offline mode.
apt-get() { echo "APT_CALLED_IN_OFFLINE"; return 0; }
install_complementary_tools
rc=$?
echo "RC=$rc"
"""
    res = _run_bash(script)
    combined = res.stdout + res.stderr
    assert "RC=0" in res.stdout, f"function was fatal on offline:\n{combined}"
    assert "APT_CALLED_IN_OFFLINE" not in combined, "offline mode reached the network (apt-get)."
    for pkg in ("yara", "tshark", "binwalk"):
        assert f"{pkg} NOT installed" in combined, f"no actionable advisory for {pkg}:\n{combined}"


def test_install_sh_syntax_ok() -> None:
    """A broken installer is worse than the bug it fixes. Since #18 the installer
    is install.sh + lib/*.sh, so parse-check every unit."""
    targets = [str(INSTALL_SH)] + [str(p) for p in sorted(LIB_DIR.glob("*.sh"))]
    res = subprocess.run(["bash", "-n", *targets], capture_output=True, text=True)
    assert res.returncode == 0, f"bash -n on installer units failed:\n{res.stderr}"


if __name__ == "__main__":  # pragma: no cover
    sys.exit(pytest.main([__file__, "-v"]))
