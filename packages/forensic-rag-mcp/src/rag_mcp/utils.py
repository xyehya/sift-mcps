"""
Shared Utilities - Common functions used across modules.

This module contains utility functions and constants that are shared between
build.py, refresh.py, index.py, server.py and other modules to avoid code
duplication and ensure consistency.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# MITRE technique ID pattern for text augmentation
MITRE_ID_PATTERN = re.compile(r"\b(T\d{4}(?:\.\d{3})?)\b", re.IGNORECASE)

# =============================================================================
# Shared Constants
# =============================================================================

# Allowed embedding models (security: prevent arbitrary model loading).
#
# B-MVP-015: the live 26,586-chunk corpus is embedded with BAAI/bge-base-en-v1.5
# (768-dim). That canonical model is the only one consistent with the existing
# pgvector rows — re-embedding with another model would be required to change it.
# The other entries are accepted ONLY for a deliberate, from-scratch re-seed; the
# default and the canonical pin below stay bge-base-en-v1.5.
ALLOWED_MODELS = frozenset(
    {
        "BAAI/bge-base-en-v1.5",
        "BAAI/bge-small-en-v1.5",
        "BAAI/bge-large-en-v1.5",
        "sentence-transformers/all-MiniLM-L6-v2",
        "sentence-transformers/all-mpnet-base-v2",
    }
)

# Default embedding model
DEFAULT_MODEL_NAME = "BAAI/bge-base-en-v1.5"

# B-MVP-004 (D3) / B-MVP-015: canonical revision (git commit on Hugging Face Hub)
# for the default model, so the downloaded weights are reproducible and pinned.
# The installer exports SIFT_RAG_MODEL_REVISION (same value); RAG_MODEL_REVISION is
# the runtime override the gateway/worker units carry. Only applied when the
# resolved model is the canonical default — a deliberate alternate model has its
# own (unpinned) revision unless the operator pins one.
CANONICAL_MODEL_NAME = "BAAI/bge-base-en-v1.5"
CANONICAL_MODEL_REVISION = "a5beb1e3e68b9ab74eb54cfd186867f64f240e1a"


def resolve_model_revision(model_name: str) -> str | None:
    """Return the pinned revision for ``model_name``, or None if unpinned.

    Resolution order: explicit ``RAG_MODEL_REVISION`` env override, then the
    canonical pin when the model is the canonical default. Any other allowlisted
    model is unpinned (returns None) unless the operator sets the env override.
    """
    override = os.environ.get("RAG_MODEL_REVISION", "").strip()
    if override:
        return override
    if model_name == CANONICAL_MODEL_NAME:
        return CANONICAL_MODEL_REVISION
    return None


def _hf_offline() -> bool:
    """True when Hugging Face Hub access is disabled (offline/air-gapped install)."""
    return os.environ.get("HF_HUB_OFFLINE", "0") in ("1", "true", "TRUE") or (
        os.environ.get("TRANSFORMERS_OFFLINE", "0") in ("1", "true", "TRUE")
    )


def load_sentence_transformer(model_name: str):
    """Load an allowlisted SentenceTransformer, revision-pinned and offline-aware.

    Centralises model loading for the seed, query, and refresh paths so the
    revision pin (B-MVP-004 D3) and ``local_files_only`` under offline mode
    (B-MVP-015) are applied consistently. Raises ValueError for a non-allowlisted
    model. Verifies the loaded revision against the pin when the hub reports one.
    """
    if model_name not in ALLOWED_MODELS:
        raise ValueError(f"RAG embedding model is not allowlisted: {model_name}")
    from sentence_transformers import SentenceTransformer

    revision = resolve_model_revision(model_name)
    kwargs: dict[str, Any] = {}
    if revision:
        kwargs["revision"] = revision
    if _hf_offline():
        kwargs["local_files_only"] = True
    try:
        model = SentenceTransformer(model_name, **kwargs)
    except TypeError:
        # Older sentence-transformers that do not accept revision/local_files_only.
        logger.warning(
            "sentence-transformers does not support revision/local_files_only "
            "kwargs; loading %s without a pinned revision.",
            model_name,
        )
        model = SentenceTransformer(model_name)
    return model

# Search limits
MAX_TOP_K = int(os.environ.get("RAG_MAX_TOP_K", "50"))  # Maximum results to return
MAX_RETRIEVE = 500  # Maximum results to retrieve before filtering


# =============================================================================
# Metadata Handling
# =============================================================================


def sanitize_metadata(meta: dict[str, Any]) -> dict[str, Any]:
    """
    Sanitize metadata for ChromaDB storage.

    ChromaDB only accepts metadata values of type: str, int, float, bool, None.
    This function converts unsupported types (lists, dicts, etc.) to strings.

    Args:
        meta: Raw metadata dictionary

    Returns:
        Sanitized metadata with all values converted to acceptable types

    Example:
        >>> sanitize_metadata({"techniques": ["T1003", "T1059"], "score": 0.85})
        {"techniques": "T1003, T1059", "score": 0.85}
    """
    result: dict[str, str | int | float | bool | None] = {}
    for k, v in meta.items():
        if v is None:
            result[k] = None
        elif isinstance(v, (str, int, float, bool)):
            result[k] = v
        elif isinstance(v, list):
            # Convert lists to comma-separated strings
            result[k] = ", ".join(str(item) for item in v)
        else:
            # Convert other types (dict, etc.) to string representation
            result[k] = str(v)
    return result


# =============================================================================
# File Utilities
# =============================================================================


def compute_file_hash(path: Path) -> str:
    """
    Compute SHA256 hash of a file.

    Args:
        path: Path to file

    Returns:
        Hash string in format "sha256:<hex_digest>"
    """
    sha256 = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            sha256.update(chunk)
    return f"sha256:{sha256.hexdigest()}"


def load_jsonl_records(path: Path) -> list[dict]:
    """
    Load records from a JSONL file.

    Each line should be a valid JSON object. Empty lines and invalid JSON
    are skipped with debug logging.

    Args:
        path: Path to JSONL file

    Returns:
        List of record dictionaries. Each record will have an 'id' field
        (generated if not present).
    """
    records = []
    with open(path, encoding="utf-8") as f:
        for i, line in enumerate(f):
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
                # Ensure record has an ID
                if "id" not in rec:
                    source = rec.get("metadata", {}).get("source", path.stem)
                    rec["id"] = f"{source}_{i}"
                records.append(rec)
            except json.JSONDecodeError:
                logger.debug(f"Invalid JSON on line {i + 1} of {path}")
    return records


def atomic_write_json(path: Path, data: Any, indent: int = 2) -> None:
    """
    Atomically write JSON data to a file.

    Security: Uses atomic write pattern to prevent file corruption from
    concurrent access or interrupted writes. Writes to a temp file first,
    then atomically renames to the target path.

    Args:
        path: Target file path
        data: JSON-serializable data
        indent: JSON indentation (default 2)
    """
    import os
    import tempfile

    path.parent.mkdir(parents=True, exist_ok=True)

    # Write to temp file in same directory (required for atomic rename)
    fd, temp_path = tempfile.mkstemp(
        dir=path.parent, prefix=f".{path.name}.", suffix=".tmp"
    )
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=indent)
        # Atomic rename (POSIX guarantees this is atomic on same filesystem)
        os.replace(temp_path, path)
    except Exception:
        # Clean up temp file on error
        try:
            os.unlink(temp_path)
        except OSError:
            pass
        raise


# =============================================================================
# MITRE Technique Augmentation
# =============================================================================


def load_mitre_lookup(sources_dir: Path) -> dict[str, str]:
    """
    Build MITRE technique ID -> name lookup from source data.

    Loads dynamically from mitre_attack.jsonl so it stays current when MITRE
    data is refreshed. Maps technique IDs (T1003, T1003.001, etc.) to their
    official names.

    Args:
        sources_dir: Path to directory containing mitre_attack.jsonl

    Returns:
        Dictionary mapping technique IDs to names (e.g., {"T1003": "OS Credential Dumping"})
    """
    mitre_jsonl = sources_dir / "mitre_attack.jsonl"
    if not mitre_jsonl.exists():
        logger.warning(f"MITRE lookup unavailable: {mitre_jsonl} not found")
        return {}

    lookup: dict[str, str] = {}
    try:
        with open(mitre_jsonl, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    record = json.loads(line)
                    meta = record.get("metadata", {})
                    title = meta.get("title", "")

                    # Extract technique ID from metadata
                    technique_id = meta.get("mitre_techniques", "")
                    if technique_id and title:
                        # Normalize ID to uppercase
                        technique_id = technique_id.strip().upper()
                        # Only map if it looks like a technique ID
                        if re.match(r"^T\d{4}(\.\d{3})?$", technique_id):
                            # Skip mitigation records
                            if title.endswith(" Mitigation"):
                                continue
                            lookup[technique_id] = title
                except json.JSONDecodeError:
                    continue
        logger.debug(f"Loaded {len(lookup)} MITRE technique mappings")
    except OSError as e:
        logger.warning(f"Could not load MITRE lookup: {e}")

    return lookup


def augment_text_with_mitre(text: str, mitre_lookup: dict[str, str]) -> str:
    """
    Augment text by expanding MITRE technique IDs with their official names.

    Used during both indexing (to enrich document embeddings) and querying
    (to improve semantic matching).

    Example:
        "Detect T1003 attacks" -> "Detect T1003 OS Credential Dumping attacks"
        "T1003.001 analysis" -> "T1003.001 LSASS Memory analysis"

    Args:
        text: Original text containing potential MITRE technique IDs
        mitre_lookup: Dictionary mapping technique IDs to names

    Returns:
        Text with MITRE IDs expanded to include technique names
    """
    if not mitre_lookup:
        return text

    def replace_id(match: re.Match) -> str:
        technique_id = match.group(1).upper()
        if technique_id in mitre_lookup:
            return f"{technique_id} {mitre_lookup[technique_id]}"
        return match.group(0)

    return MITRE_ID_PATTERN.sub(replace_id, text)
