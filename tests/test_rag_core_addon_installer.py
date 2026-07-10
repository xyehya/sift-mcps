"""Installer contract tests for the first-party RAG core add-on."""

from __future__ import annotations

import subprocess
from types import SimpleNamespace

from _installer_support import REPO_ROOT
from sift_gateway import rag_provision
from sift_gateway.rag_provision import check_rag_current, verify_knowledge_manifest

RAG_SETUP = REPO_ROOT / "scripts" / "core-addons" / "setup-rag.sh"
RAG_KNOWLEDGE = REPO_ROOT / "packages" / "forensic-rag-mcp" / "knowledge"


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
    assert "--check-current" in source
    assert "skipping unchanged embeddings" in source


def test_rag_corpus_sha256_manifest_matches_shipped_files():
    """The first-party pack must refuse a changed or surprise corpus file."""
    verify_knowledge_manifest(RAG_KNOWLEDGE, RAG_KNOWLEDGE / "manifest.sha256")


def test_rag_current_check_skips_only_an_exact_verified_database(monkeypatch):
    expected = {"chunks": 4318, "documents": 44, "collections": 2}
    monkeypatch.setenv("SIFT_CONTROL_PLANE_DSN", "postgresql://local/test")
    monkeypatch.setattr(rag_provision, "verify_knowledge_manifest", lambda *_: None)
    monkeypatch.setattr(
        "rag_mcp.pgvector_seed.seed_knowledge_from_dir",
        lambda **_: SimpleNamespace(public_dict=lambda: expected),
    )
    monkeypatch.setattr(
        "rag_mcp.pgvector_store.PgVectorRagStore.knowledge_stats",
        lambda _self: {
            "chunk_count": 4318,
            "document_count": 44,
            "collection_count": 2,
            "source_count": 20,
            "embedding_dim": 768,
            "embedding_model": "BAAI/bge-base-en-v1.5",
        },
    )

    result = check_rag_current(
        knowledge_dir=RAG_KNOWLEDGE,
        manifest_path=RAG_KNOWLEDGE / "manifest.sha256",
        model_name="BAAI/bge-base-en-v1.5",
        model_revision="a5beb1e3e68b9ab74eb54cfd186867f64f240e1a",
    )
    assert result["current"] is True

    expected["chunks"] += 1
    result = check_rag_current(
        knowledge_dir=RAG_KNOWLEDGE,
        manifest_path=RAG_KNOWLEDGE / "manifest.sha256",
        model_name="BAAI/bge-base-en-v1.5",
        model_revision="a5beb1e3e68b9ab74eb54cfd186867f64f240e1a",
    )
    assert result["current"] is False


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
