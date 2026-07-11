"""Fail-closed contract tests for the OpenCTI shared-search target path."""

from __future__ import annotations

import subprocess
import tomllib

from _installer_support import REPO_ROOT

SHARED_COMPOSE = REPO_ROOT / "docker-compose.opencti-shared.yml"
ROLE = REPO_ROOT / "configs" / "opensearch" / "security" / "opencti-platform-role.yml"
CHECK = REPO_ROOT / "scripts" / "prepare-opencti-shared-opensearch.sh"
SETUP = REPO_ROOT / "scripts" / "setup-addon.sh"
TUPLE = REPO_ROOT / "configs" / "opencti" / "shared-target-versions.env"
PROVISION = REPO_ROOT / "scripts" / "provision-opencti-shared-opensearch.py"
API_IDENTITIES = REPO_ROOT / "scripts" / "provision-opencti-api-identities.py"
ORCHESTRATOR = REPO_ROOT / "scripts" / "provision-opencti-shared-target.sh"
GATEWAY_UNIT = REPO_ROOT / "configs" / "systemd" / "sift-gateway.service"


def test_shared_compose_has_no_dedicated_search_and_keeps_tls_prefix_boundary() -> None:
    source = SHARED_COMPOSE.read_text(encoding="utf-8")
    assert "name: sift-opencti-shared" in source
    assert "opencti-opensearch" not in source
    assert "ELASTICSEARCH__ENGINE_SELECTOR=opensearch" in source
    assert "ELASTICSEARCH__ENGINE_CHECK=true" in source
    assert "ELASTICSEARCH__INDEX_PREFIX=opencti" in source
    assert "ELASTICSEARCH__SSL__REJECT_UNAUTHORIZED=true" in source
    assert "node-0.example.com" in source
    assert "external: true" in source
    assert "internal: true" in source
    assert "127.0.0.1:8080:8080" in source
    assert "RABBITMQ__PASSWORD=${OPENCTI_RABBITMQ_PASSWORD" in source
    assert "MINIO__SECRET_KEY=${OPENCTI_MINIO_SECRET_KEY" in source
    assert "OPENCTI_TOKEN=${OPENCTI_WORKER_TOKEN" in source
    assert "APP__ADMIN__PASSWORD=${OPENCTI_ADMIN_PASSWORD" in source
    assert "APP__ADMIN__PASSWORD=${OPENCTI_ADMIN_TOKEN" not in source
    assert source.count('user: "999:999"') == 2
    assert "/data:uid=999,gid=999,mode=0700" in source
    assert "opencti-redis:/data" not in source
    assert "RABBITMQ_DEFAULT_PASS=${OPENCTI_RABBITMQ_PASSWORD" in source
    assert "MINIO_ROOT_PASSWORD=${OPENCTI_MINIO_SECRET_KEY" in source
    assert "RABBITMQ__PASSWORD=${OPENCTI_ADMIN_TOKEN" not in source
    assert "MINIO__SECRET_KEY=${OPENCTI_ADMIN_TOKEN" not in source
    assert source.count("cap_drop: [ALL]") == 5
    assert source.count("security_opt: [no-new-privileges:true]") == 5


def test_opencti_role_is_prefix_only_and_not_security_admin() -> None:
    source = ROLE.read_text(encoding="utf-8")
    assert "opencti*" in source
    for forbidden in ("all_access", "readall", "restapi:admin", "index_patterns: ['*']"):
        assert forbidden not in source
    assert "indices_all" in source


def test_shared_check_is_read_only_and_requires_secure_core_contract() -> None:
    source = CHECK.read_text(encoding="utf-8")
    assert "docker compose -f \"$shared_compose\" config --quiet" in source
    assert "docker compose.* up" not in source
    assert "docker compose.* down" not in source
    result = subprocess.run(
        ["bash", str(CHECK), "--check"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode != 0
    assert "OPENCTI_OPENSEARCH_CA" in result.stderr
    assert "OPENSEARCH_INITIAL_ADMIN_PASSWORD" in source
    assert "https://localhost:9200" in source
    assert "OPENCTI_OPENSEARCH_CHECK_URL" in source
    assert "ssl.create_default_context" in source
    assert 'parsed.hostname not in {"127.0.0.1", "localhost", "::1"}' in source


def test_acceptance_tuple_is_exact_and_matches_package_metadata() -> None:
    values = dict(
        line.split("=", 1)
        for line in TUPLE.read_text(encoding="utf-8").splitlines()
        if line and not line.startswith("#")
    )
    assert values["OPENCTI_VERSION"] == "7.260710.0"
    assert values["PYCTI_VERSION"] == values["OPENCTI_VERSION"]
    assert values["OPENSEARCH_VERSION"] == "3.5.0"
    assert values["OPENCTI_PLATFORM_IMAGE"].startswith("opencti/platform@sha256:")
    assert values["OPENCTI_WORKER_IMAGE"].startswith("opencti/worker@sha256:")
    project = tomllib.loads(
        (REPO_ROOT / "packages" / "opencti-mcp" / "pyproject.toml").read_text(
            encoding="utf-8"
        )
    )
    assert f'pycti=={values["PYCTI_VERSION"]}' in project["project"]["dependencies"]


def test_external_helper_exposes_only_explicit_shared_check() -> None:
    source = SETUP.read_text(encoding="utf-8")
    assert "--shared-opensearch-check" in source
    assert "prepare-opencti-shared-opensearch.sh" in source
    assert 'source "$REPO_ROOT/install.sh"' not in source
    assert "provision-opencti-shared-target.sh" in source
    assert "prepare_opencti_secrets && install_opencti" not in source
    assert 'die "--provision requested but Docker is unavailable.' in source


def test_identity_provisioner_proves_positive_and_negative_index_boundaries() -> None:
    source = PROVISION.read_text(encoding="utf-8")
    assert "secrets.token_urlsafe(48)" in source
    assert 'proof_index = f"opencti-security-proof-' in source
    assert 'case_proof = f"case-security-negative-proof-' in source
    assert "negative not in {401, 403}" in source
    assert "os.chmod(temp_path, 0o600)" in source
    assert "os.replace(temp_path, output_path)" in source
    assert "OPENCTI_OPENSEARCH_PASSWORD=" in source
    assert "print(platform_password" not in source
    assert "os.chown(output_path, 0, 0)" in source
    assert '"/_plugins/_security/api/audit"' in source
    assert '"/config/audit/log_request_body", "value": False' in source
    assert '"/config/audit/disabled_rest_categories", "value": ["AUTHENTICATED"]' in source


def test_opencti_api_identities_are_distinct_and_gateway_is_query_only() -> None:
    source = API_IDENTITIES.read_text(encoding="utf-8")
    assert '{"BYPASS", "APIACCESS", "APIACCESS_USETOKEN"}' in source
    assert '{"KNOWLEDGE", "APIACCESS", "APIACCESS_USETOKEN"}' in source
    assert 'len({admin_token, worker, query}) != 3' in source
    assert '"SIFT_OPENCTI_URL": "http://127.0.0.1:8080"' in source
    assert '"SIFT_OPENCTI_TOKEN": query' in source
    assert "atomic_env(stack_path, stack, 0, 0)" in source
    unit = GATEWAY_UNIT.read_text(encoding="utf-8")
    assert "EnvironmentFile=-${SIFT_HOME}/opencti-query.env" in unit
    assert "opencti-stack.env" not in unit
    assert "opencti-shared.env" not in unit


def test_shared_orchestrator_is_fail_closed_and_uses_pinned_compose() -> None:
    source = ORCHESTRATOR.read_text(encoding="utf-8")
    assert "set -Eeuo pipefail" in source
    assert "prepare-opencti-shared-opensearch.sh" in source
    assert "provision-opencti-shared-opensearch.py" in source
    assert "provision-opencti-api-identities.py" in source
    assert "docker-compose.opencti-shared.yml" in source
    assert "docker-compose.opencti.yml" not in source
    assert "|| warn" not in source
