"""Fail-closed contract tests for the OpenCTI shared-search target path."""

from __future__ import annotations

import subprocess
import tomllib

from _installer_support import REPO_ROOT

SHARED_COMPOSE = REPO_ROOT / "docker-compose.opencti-shared.yml"
CONNECTORS_COMPOSE = REPO_ROOT / "docker-compose.opencti-connectors.yml"
ROLE = REPO_ROOT / "configs" / "opensearch" / "security" / "opencti-platform-role.yml"
CHECK = REPO_ROOT / "scripts" / "prepare-opencti-shared-opensearch.sh"
SETUP = REPO_ROOT / "scripts" / "setup-addon.sh"
TUPLE = REPO_ROOT / "configs" / "opencti" / "shared-target-versions.env"
PROVISION = REPO_ROOT / "scripts" / "provision-opencti-shared-opensearch.py"
API_IDENTITIES = REPO_ROOT / "scripts" / "provision-opencti-api-identities.py"
ORCHESTRATOR = REPO_ROOT / "scripts" / "provision-opencti-shared-target.sh"
FEED_VERIFY = REPO_ROOT / "scripts" / "verify-opencti-public-feeds.py"
MITRE_BOOTSTRAP = REPO_ROOT / "scripts" / "bootstrap-opencti-mitre-provenance.py"
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
    assert "using exact cached digest" in source
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
    for key in (
        "OPENCTI_CONNECTOR_MITRE_IMAGE",
        "OPENCTI_CONNECTOR_CISA_KEV_IMAGE",
        "OPENCTI_CONNECTOR_THREATFOX_IMAGE",
        "OPENCTI_CONNECTOR_URLHAUS_IMAGE",
    ):
        assert values[key].startswith("opencti/connector-")
        assert "@sha256:" in values[key]
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
    assert source.index('stage_runtime_command "opencti-mcp" "opencti"') < source.index(
        'bash "$REPO_ROOT/scripts/provision-opencti-shared-target.sh"'
    )


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
    assert 'connector_capabilities | {"BYPASS"}' in source
    assert '{"KNOWLEDGE", "APIACCESS", "APIACCESS_USETOKEN"}' in source
    assert '"CONNECTORAPI"' in source
    assert '"KNOWLEDGE_KNUPDATE"' in source
    assert '"MODULES"' in source
    for capability in (
        "KNOWLEDGE_KNUPDATE_KNBYPASSFIELDS",
        "KNOWLEDGE_KNUPDATE_KNBYPASSREFERENCE",
        "SETTINGS_SETKILLCHAINPHASES",
        "SETTINGS_SETLABELS",
        "SETTINGS_SETMARKINGS",
        "SETTINGS_SETVOCABULARIES",
    ):
        assert f'"{capability}"' in source
    for forbidden in ("KNDELETE", "KNMERGE", "KNUPLOAD", "TAXIIAPI", "BYPASS\","):
        assert forbidden not in source.split("connector_capabilities =", 1)[1].split("}", 1)[0]
    assert 'if "BYPASS" in names and group["name"] != "SIFT Workers"' in source
    assert 'default_caps - {"KNOWLEDGE"}' in source
    assert 'ensure_group("SIFT Workers", worker_role, True)' in source
    assert 'ensure_group("SIFT Public Feed Connectors", connector_role, True)' in source
    assert '"key": "auto_new_marking"' in source
    assert 'relationship_type: \\"accesses-to\\"' in source
    assert "ensure_existing_markings(worker_group)" in source
    assert "ensure_existing_markings(connector_group)" in source
    assert "ensure_existing_markings(query_group)" not in source
    assert 'opencti-connectors.env' in source
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
    assert "install -d -m 700 -o root -g root /var/lib/sift/.sift" not in source
    assert "docker-compose.opencti-connectors.yml" in source
    assert "Offline mode: public-feed connectors are prepared but not started" in source
    assert "verify-opencti-public-feeds.py" in source
    assert "bootstrap-opencti-mitre-provenance.py" in source
    assert 'OPENCTI_WORKER_COUNT="${SIFT_OPENCTI_WORKERS:-8}"' in source
    assert "must be an integer from 1 through 8" in source
    assert '--scale worker="$OPENCTI_WORKER_COUNT"' in source
    assert 'docker image inspect "$image"' in source


def test_public_feed_connectors_are_pinned_isolated_and_hardened() -> None:
    source = CONNECTORS_COMPOSE.read_text(encoding="utf-8")
    assert "name: sift-opencti-connectors" in source
    assert source.count("OPENCTI_TOKEN:") == 4
    assert "OPENCTI_ADMIN_TOKEN" not in source
    assert "OPENCTI_WORKER_TOKEN" not in source
    assert "OPENCTI_QUERY_TOKEN" not in source
    assert "OPENSEARCH" not in source
    assert "sift-net" not in source
    assert "ports:" not in source
    assert "opencti-app-net" in source
    assert "feed-egress" in source
    assert "cap_drop: [ALL]" in source
    assert "security_opt: [no-new-privileges:true]" in source
    assert "read_only: true" in source
    assert 'user: "65532:65532"' in source
    assert "pids_limit:" in source
    assert "mem_limit:" in source
    assert "cpus:" in source
    assert "MITRE_REMOVE_STATEMENT_MARKING: \"false\"" in source
    assert "CONNECTOR_SCOPE: mitre" not in source
    assert "d4a34a19eb60dcd0a9d15a456da842a42e1003fc" in source
    assert "CISA_CREATE_INFRASTRUCTURES: \"false\"" in source
    assert "THREATFOX_IMPORT_OFFLINE: \"false\"" in source
    assert "URLHAUS_IMPORT_OFFLINE: \"false\"" in source
    assert "URLHAUS_INTERVAL" not in source


def test_public_feed_readiness_is_bounded_and_source_shaped() -> None:
    source = FEED_VERIFY.read_text(encoding="utf-8")
    assert '"http://127.0.0.1:8080/graphql"' in source
    assert '"SIFT_OPENCTI_FEED_READY_TIMEOUT", "1800"' in source
    assert "timeout < 30 or timeout > 3600" in source
    assert '"MITRE ATT&CK"' in source
    assert '"CISA KEV"' in source
    assert '"ThreatFox"' in source
    assert '"Abuse.ch URLhaus"' in source
    for entity in ("attackPatterns", "vulnerabilities", "indicators", "stixCyberObservables"):
        assert f'"{entity}"' in source
    assert 'counts["attackPatterns"] >= 675' in source


def test_mitre_provenance_bootstrap_preserves_cyclic_attribution() -> None:
    source = MITRE_BOOTSTRAP.read_text(encoding="utf-8")
    assert "d4a34a19eb60dcd0a9d15a456da842a42e1003fc" in source
    assert 'IDENTITY_ID = "identity--c78cb6e5-0c4b-4611-8297-d1b8b55e40b5"' in source
    assert 'MARKING_ID = "marking-definition--fa42a846-8d90-4e51-bc29-71d5b4802168"' in source
    assert "MAX_BYTES = 64 * 1024 * 1024" in source
    assert 'unmarked_identity.pop("object_marking_refs", None)' in source
    assert "client.stix2.import_object(unmarked_identity, update=True)" in source
    assert "client.stix2.import_object(marking, update=True)" in source
    assert "client.stix2.import_object(identity, update=True)" in source
    assert "ssl.create_default_context()" in source
