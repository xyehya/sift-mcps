"""Fail-on-revert contract for the secure core OpenSearch install path."""

from __future__ import annotations

from _installer_support import REPO_ROOT


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
    assert "openssl verify -CAfile" in opensearch
    assert "host: https://localhost:9200" in config
    assert "verify_certs: true" in config
    assert "ca_certs=config.get(\"ca_certs\")" in client
