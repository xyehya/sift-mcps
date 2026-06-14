"""B-MVP-032: startup manifest-drift detection (registered vs on-disk).

These tests exercise the pure sha-compare/decision logic with injected manifest
dicts and a stub registry record, so they require no live DB and no psycopg.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any

from sift_gateway.mcp_backends_registry import (
    ManifestDriftFinding,
    detect_manifest_drift,
    log_manifest_drift,
    manifest_sha256,
)


@dataclass
class _StubRecord:
    name: str
    manifest_sha256: str
    connection: dict[str, Any]
    enabled: bool = True


def _manifest(case_args: list[str]) -> dict[str, Any]:
    return {
        "namespace": "opensearch",
        "tools": [
            {"name": "opensearch_search", "safe_case_argument_names": case_args}
        ],
    }


def test_no_drift_when_on_disk_matches_registered():
    on_disk = _manifest([])
    record = _StubRecord(
        name="opensearch-mcp",
        manifest_sha256=manifest_sha256(on_disk),
        connection={"type": "stdio", "command": "x"},
    )
    findings = detect_manifest_drift([record], load_manifest=lambda n, c: on_disk)
    assert findings == []


def test_drift_detected_when_on_disk_changed():
    # Registered with the OLD manifest; on-disk gained case_dir (the B-MVP-029
    # autosave scenario).
    registered = _manifest([])
    on_disk = _manifest(["case_dir"])
    record = _StubRecord(
        name="opensearch-mcp",
        manifest_sha256=manifest_sha256(registered),
        connection={"type": "stdio", "command": "x"},
    )
    findings = detect_manifest_drift([record], load_manifest=lambda n, c: on_disk)
    assert len(findings) == 1
    f = findings[0]
    assert f.name == "opensearch-mcp"
    assert f.drifted is True
    assert f.registered_sha == manifest_sha256(registered)
    assert f.on_disk_sha == manifest_sha256(on_disk)
    assert f.registered_sha != f.on_disk_sha


def test_record_skipped_when_no_on_disk_manifest():
    # Remote/library backends return None — cannot assess local drift, no finding.
    record = _StubRecord(
        name="remote-addon",
        manifest_sha256="deadbeef",
        connection={"type": "http", "url": "https://x/mcp"},
    )
    findings = detect_manifest_drift([record], load_manifest=lambda n, c: None)
    assert findings == []


def test_loader_exception_does_not_block_other_records():
    good_manifest = _manifest(["case_dir"])
    bad = _StubRecord(name="broken", manifest_sha256="abc", connection={"type": "stdio"})
    good = _StubRecord(
        name="ok",
        manifest_sha256="stale-sha",
        connection={"type": "stdio", "command": "x"},
    )

    def _load(name: str, _conn: dict[str, Any]):
        if name == "broken":
            raise RuntimeError("boom")
        return good_manifest

    findings = detect_manifest_drift([bad, good], load_manifest=_load)
    assert [f.name for f in findings] == ["ok"]


def test_log_manifest_drift_emits_warning_with_both_shas(caplog):
    finding = ManifestDriftFinding(
        name="opensearch-mcp",
        registered_sha="stale111",
        on_disk_sha="fresh222",
    )
    log = logging.getLogger("test-drift")
    with caplog.at_level(logging.WARNING, logger="test-drift"):
        log_manifest_drift([finding], log=log)
    msgs = [r.getMessage() for r in caplog.records if r.levelno == logging.WARNING]
    assert any("opensearch-mcp" in m and "stale111" in m and "fresh222" in m for m in msgs)
