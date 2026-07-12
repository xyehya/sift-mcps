"""Fail-on-revert teardown contract for the shared OpenCTI target."""

from __future__ import annotations

from _installer_support import REPO_ROOT


def test_opencti_teardown_targets_only_the_shared_addon_stack() -> None:
    source = (REPO_ROOT / "scripts" / "uninstall.sh").read_text(encoding="utf-8")
    assert "docker-compose.opencti-shared.yml" in source
    assert "docker-compose.opencti-connectors.yml" in source
    assert "docker-compose.opencti.yml" not in source
    for env_file in (
        "opencti-stack.env",
        "opencti-shared.env",
        "opencti-connectors.env",
        "opencti-query.env",
    ):
        assert env_file in source
    assert "opencti-opensearch" not in source
    assert "sift-opencti-net" not in source
    # Volumes are force-purged by name; compose down is best-effort only.
    assert "force_purge_sift_docker_state" in source
    assert "sift-opencti-shared_" in source
