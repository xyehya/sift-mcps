"""Installer contract tests for the first-party RAG core add-on."""

from __future__ import annotations

import hashlib
import subprocess

from _installer_support import REPO_ROOT

RAG_SETUP = REPO_ROOT / "scripts" / "core-addons" / "setup-rag.sh"
RAG_SNAPSHOT = (
    REPO_ROOT
    / "artifacts"
    / "qwen3-embedding-0.6b-1024-sift-rag-v1.tar.zst"
)


def test_rag_core_addon_help_is_noninteractive_and_has_no_top_level_installer_source():
    result = subprocess.run(
        ["bash", str(RAG_SETUP), "--help"],
        cwd=str(REPO_ROOT),
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr
    assert "--install" in result.stdout
    source = RAG_SETUP.read_text(encoding="utf-8")
    assert 'source "$REPO_DIR/install.sh"' not in source
    assert "sift_source_first_party_addon_libraries" in source
    assert "rag-mcp-seed-pgvector" not in source
    assert '"SIFT_CONTROL_PLANE_DSN": "SIFT_CONTROL_PLANE_DSN"' not in source
    assert "rag_mcp.pgvector_snapshot_import" in source
    assert "pgvector_seed" not in source
    assert "qwen3-embedding-0.6b-1024-sift-rag-v1.tar.zst" in source


def test_rag_snapshot_sha256_matches_installer_pin():
    digest = hashlib.sha256(RAG_SNAPSHOT.read_bytes()).hexdigest()
    assert digest == "1030d3901d116c1c4fe7e82148da2eb07857afaebb0702a01aa2532273b870b4"


def test_rag_installer_exactly_allowlists_snapshot_members():
    source = RAG_SETUP.read_text(encoding="utf-8")
    for member in (
        "qwen3-embedding-0.6b-1024/embeddings.f32.npy",
        "qwen3-embedding-0.6b-1024/manifest.json",
        "qwen3-embedding-0.6b-1024/records.jsonl",
    ):
        assert member in source
    assert "snapshot member set is invalid" in source


def test_legacy_generic_seeder_cannot_reintroduce_rag_stdio_dsn_wiring():
    source = (REPO_ROOT / "lib" / "examiner.sh").read_text(encoding="utf-8")
    generic = source[
        source.index("seed_addon_backends() {") : source.index(
            "# A1-BOOTSTRAP", source.index("seed_addon_backends() {")
        )
    ]
    assert '"forensic-rag-mcp" \\' not in generic
    assert '"SIFT_CONTROL_PLANE_DSN": "SIFT_CONTROL_PLANE_DSN"' not in generic
    assert "reconcile_first_party_gateway_backend" in source


def test_registry_migration_allows_only_credential_free_gateway_shape():
    migration = next(
        (REPO_ROOT / "supabase" / "migrations").glob(
            "202607100900_mcp_backends_gateway_transport.sql"
        )
    ).read_text(encoding="utf-8")
    assert "transport in ('stdio', 'http', 'gateway')" in migration
    assert "connection->>'type' = 'gateway'" in migration
    assert "not (connection ? 'env_refs')" in migration
    assert "not (connection ? 'command')" in migration
