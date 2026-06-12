"""B-MVP-004/B-MVP-015: RAG embedding-model revision pin + offline resolution."""

import pytest

from rag_mcp.utils import (
    CANONICAL_MODEL_NAME,
    CANONICAL_MODEL_REVISION,
    DEFAULT_MODEL_NAME,
    _hf_offline,
    resolve_model_revision,
)


def test_default_is_canonical_bge():
    assert DEFAULT_MODEL_NAME == "BAAI/bge-base-en-v1.5"
    assert CANONICAL_MODEL_NAME == DEFAULT_MODEL_NAME


def test_canonical_model_resolves_pinned_revision(monkeypatch):
    monkeypatch.delenv("RAG_MODEL_REVISION", raising=False)
    assert resolve_model_revision(CANONICAL_MODEL_NAME) == CANONICAL_MODEL_REVISION


def test_env_override_takes_precedence(monkeypatch):
    monkeypatch.setenv("RAG_MODEL_REVISION", "abc123")
    assert resolve_model_revision(CANONICAL_MODEL_NAME) == "abc123"
    # Override applies to any model when explicitly set.
    assert resolve_model_revision("BAAI/bge-small-en-v1.5") == "abc123"


def test_non_canonical_model_is_unpinned_without_override(monkeypatch):
    monkeypatch.delenv("RAG_MODEL_REVISION", raising=False)
    assert resolve_model_revision("BAAI/bge-small-en-v1.5") is None


@pytest.mark.parametrize("var", ["HF_HUB_OFFLINE", "TRANSFORMERS_OFFLINE"])
def test_offline_detection(monkeypatch, var):
    monkeypatch.delenv("HF_HUB_OFFLINE", raising=False)
    monkeypatch.delenv("TRANSFORMERS_OFFLINE", raising=False)
    assert _hf_offline() is False
    monkeypatch.setenv(var, "1")
    assert _hf_offline() is True
