"""Fail-on-revert teardown contract for the shared OpenCTI target."""

from __future__ import annotations

from _installer_support import REPO_ROOT


def test_opencti_teardown_targets_only_the_shared_addon_stack() -> None:
    source = (REPO_ROOT / "scripts" / "uninstall.sh").read_text(encoding="utf-8")
    section = source.split("teardown_opencti()", 1)[1].split("teardown_opensearch()", 1)[0]
    assert "docker-compose.opencti-shared.yml" in section
    assert "docker-compose.opencti-connectors.yml" in section
    assert "docker-compose.opencti.yml" not in section
    for env_file in (
        "opencti-stack.env",
        "opencti-shared.env",
        "opencti-connectors.env",
        "opencti-query.env",
    ):
        assert env_file in section
    assert "opencti-opensearch" not in section
    assert "sift-opencti-net" not in section
