"""BGE query embedder for the pgvector RAG plane (BATCH-OSX-RAG).

Moved here from the gateway ``rag_bridge._embed_query``. This is the runtime
query embedder for ``kb_search_knowledge``: it loads the allowlisted BGE model
once and encodes a query string into the 768-dim vector that
``app.rag_search`` expects. ``sentence-transformers`` is a REQUIRED runtime
dependency for this path (only ``chromadb`` is optional now).

Security:
  - Model allowlist (``ALLOWED_MODELS``) prevents arbitrary model loading.
  - Query length is bounded to prevent DoS.
  - The model is cached per process so repeated queries stay fast.
"""

from __future__ import annotations

import logging
import threading

from .utils import ALLOWED_MODELS, DEFAULT_MODEL_NAME

logger = logging.getLogger(__name__)

EMBEDDING_DIM = 768
MAX_QUERY_LENGTH = 1000


class QueryEmbeddingError(Exception):
    """Raised when a query cannot be embedded (bad input or model unavailable)."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


class QueryEmbedder:
    """Lazy, process-cached BGE query embedder over the allowlisted model."""

    def __init__(self, model_name: str = DEFAULT_MODEL_NAME) -> None:
        if model_name not in ALLOWED_MODELS:
            raise QueryEmbeddingError("rag_embedding_model_not_allowed")
        self._model_name = model_name
        self._model = None
        self._lock = threading.Lock()

    def _load_model(self):
        if self._model is not None:
            return self._model
        with self._lock:
            if self._model is None:
                try:
                    from .utils import load_sentence_transformer

                    # B-MVP-004/B-MVP-015: revision-pinned, offline-aware load.
                    self._model = load_sentence_transformer(self._model_name)
                except ImportError as exc:  # pragma: no cover - deployment env
                    raise QueryEmbeddingError(
                        "rag_embedding_model_unavailable"
                    ) from exc
        return self._model

    def embed(self, query: str) -> list[float]:
        """Embed a query string into a 768-dim BGE vector."""
        if not query or not query.strip():
            raise QueryEmbeddingError("rag_query_required")
        if len(query) > MAX_QUERY_LENGTH:
            raise QueryEmbeddingError("rag_query_too_long")
        model = self._load_model()
        vector = model.encode(query)
        out = [float(v) for v in vector.tolist()]
        if len(out) != EMBEDDING_DIM:  # pragma: no cover - model contract
            raise QueryEmbeddingError("rag_embedding_dim_mismatch")
        return out
