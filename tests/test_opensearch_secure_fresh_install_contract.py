"""Fail-on-revert contract for the secure core OpenSearch install path."""

from __future__ import annotations

from pathlib import Path

from _installer_support import REPO_ROOT
from _installer_support import run_bash as _run_bash

# Sentinel only — never a real credential (CodeGuard: no hardcoded secrets).
_SENTINEL_ADMIN_PASSWORD = "TEST_SENTINEL_OPENSEARCH_PASSWORD_NOT_A_REAL_SECRET"


def test_core_compose_is_tls_authenticated_not_security_disabled() -> None:
    compose = (REPO_ROOT / "docker-compose.yml").read_text(encoding="utf-8")
    assert "DISABLE_SECURITY_PLUGIN=true" not in compose
    assert "OPENSEARCH_INITIAL_ADMIN_PASSWORD" in compose
    assert "https://localhost:9200" in compose
    assert "127.0.0.1:9200:9200" in compose


def test_legacy_insecure_profile_is_explicit_and_separate() -> None:
    dev_profile = (REPO_ROOT / "docker-compose.dev-insecure.yml").read_text(encoding="utf-8")
    assert "DISABLE_SECURITY_PLUGIN=true" in dev_profile
    assert "services:" in dev_profile
    assert "image:" not in dev_profile


def test_installer_generates_and_uses_a_verified_ca_bound_config() -> None:
    installer = (REPO_ROOT / "install.sh").read_text(encoding="utf-8")
    config = (REPO_ROOT / "lib" / "config.sh").read_text(encoding="utf-8")
    opensearch = (REPO_ROOT / "lib" / "opensearch.sh").read_text(encoding="utf-8")
    client = (REPO_ROOT / "packages" / "opensearch-mcp" / "src" / "opensearch_mcp" / "client.py").read_text(encoding="utf-8")
    core_phase = installer[installer.index("# Track whether OpenSearch came up"):]
    start_call = core_phase.index("\n  start_opensearch")
    assert core_phase.index("ensure_opensearch_admin_credentials") < start_call
    assert start_call < core_phase.index("\n  write_opensearch_config")
    assert "openssl rand -base64" in opensearch
    assert "--cacert" in opensearch
    assert "sudo_if_needed curl" in opensearch
    assert "openssl verify -CAfile" in opensearch
    assert '_stage_opensearch_private_client_config "$tmp_config" "$tmp_ca"' in opensearch
    assert 'OPENSEARCH_CONFIG="$tmp_config" "$SYSTEM_PYTHON"' in opensearch
    assert "host: https://localhost:9200" in config
    assert "verify_certs: true" in config
    assert 'svc_test_f "$SIFT_HOME/opensearch-root-ca.pem"' in config
    assert "ca_certs=config.get(\"ca_certs\")" in client
    assert 'ssl_assert_hostname="localhost"' in client


def test_opensearch_config_writers_trap_secret_temps_on_exit() -> None:
    """Static fail-on-revert: both writers must arm the established EXIT trap."""
    config = (REPO_ROOT / "lib" / "config.sh").read_text(encoding="utf-8")
    for fn in ("write_opensearch_config", "write_opensearch_env"):
        start = config.index(f"{fn}() {{")
        end = config.index("\n}", start)
        body = config[start:end]
        assert "trap 'rm -f \"${tmp:-}\"; trap - EXIT' EXIT" in body, (
            f"{fn} must trap-clean its mktemp on EXIT so a failed "
            "svc_install_file cannot leave secrets in TMPDIR"
        )
        assert "trap - EXIT" in body
        # TLS hardening must survive the cleanup re-introduction.
        if fn == "write_opensearch_config":
            assert "host: https://localhost:9200" in body
            assert "verify_certs: true" in body
            assert "http://127.0.0.1:9200" not in body
            assert "verify_certs: false" not in body


def test_write_opensearch_config_cleans_secret_temp_when_install_fails(
    tmp_path: Path,
) -> None:
    """Behavioral fail-on-revert: svc_install_file failure must leave TMPDIR
    free of the rendered password (EXIT trap, not only the happy-path rm)."""
    sift_home = tmp_path / "sift-home"
    tmpdir = tmp_path / "tmpdir"
    sift_home.mkdir()
    tmpdir.mkdir()
    (sift_home / "opensearch-root-ca.pem").write_text(
        "TEST_SENTINEL_CA_PEM_NOT_A_REAL_CERT\n", encoding="utf-8"
    )
    (sift_home / "opensearch-admin.env").write_text(
        f"SIFT_OPENSEARCH_ADMIN_PASSWORD={_SENTINEL_ADMIN_PASSWORD}\n",
        encoding="utf-8",
    )

    script = f"""
set -uo pipefail
export TMPDIR="{tmpdir}"
export SIFT_HOME="{sift_home}"
source ./install.sh
# Avoid sudo: operator-owned fixtures under tmp_path are readable directly.
svc_test_f() {{ test -f "$1"; }}
svc_read() {{ cat "$1" 2>/dev/null || true; }}
svc_install_file() {{ return 1; }}
# set -e is active after source; a failing install must abort via EXIT trap.
write_opensearch_config
echo "REACHED_END_SHOULD_NOT_HAPPEN"
"""
    res = _run_bash(script)
    assert res.returncode != 0, (
        f"expected svc_install_file failure to abort:\n{res.stdout}\n{res.stderr}"
    )
    assert "REACHED_END_SHOULD_NOT_HAPPEN" not in res.stdout
    leftovers = list(tmpdir.iterdir())
    leaked = [
        p
        for p in leftovers
        if _SENTINEL_ADMIN_PASSWORD
        in p.read_text(encoding="utf-8", errors="replace")
    ]
    assert leaked == [], f"sentinel password leaked in leftover temps: {leaked}"
    assert leftovers == [], f"secret-bearing temps left in TMPDIR: {leftovers}"


def test_write_opensearch_env_cleans_temp_when_install_fails(tmp_path: Path) -> None:
    """Same EXIT-trap contract for write_opensearch_env (0600 gateway env)."""
    sift_home = tmp_path / "sift-home"
    tmpdir = tmp_path / "tmpdir"
    sift_home.mkdir()
    tmpdir.mkdir()

    script = f"""
set -uo pipefail
export TMPDIR="{tmpdir}"
export SIFT_HOME="{sift_home}"
export SIFT_OPENSEARCH_ENABLED=true
source ./install.sh
svc_test_f() {{ test -f "$1"; }}
svc_install_file() {{ return 1; }}
write_opensearch_env
echo "REACHED_END_SHOULD_NOT_HAPPEN"
"""
    res = _run_bash(script)
    assert res.returncode != 0, (
        f"expected svc_install_file failure to abort:\n{res.stdout}\n{res.stderr}"
    )
    assert "REACHED_END_SHOULD_NOT_HAPPEN" not in res.stdout
    leftovers = list(tmpdir.iterdir())
    assert leftovers == [], f"rendered env temps left in TMPDIR: {leftovers}"
