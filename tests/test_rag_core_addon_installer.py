"""Installer contract tests for the first-party RAG core add-on."""

from __future__ import annotations

import subprocess

from _installer_support import REPO_ROOT
from sift_gateway.rag_provision import verify_knowledge_manifest

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


def test_rag_corpus_sha256_manifest_matches_shipped_files():
    """The first-party pack must refuse a changed or surprise corpus file."""
    verify_knowledge_manifest(RAG_KNOWLEDGE, RAG_KNOWLEDGE / "manifest.sha256")


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
