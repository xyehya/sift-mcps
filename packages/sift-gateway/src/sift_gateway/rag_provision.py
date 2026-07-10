"""Installer-owned provisioning for the first-party RAG knowledge pack.

This module is deliberately in ``sift_gateway`` rather than the RAG MCP
server.  It is started only by the trusted installer authority path, which may
use the control-plane DSN to populate pgvector.  The RAG MCP runtime never
receives that credential.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path


class RagProvisionError(RuntimeError):
    """A deterministic pack provisioning precondition was not met."""


def verify_knowledge_manifest(knowledge_dir: Path, manifest_path: Path) -> None:
    """Fail closed unless the shipped corpus exactly matches its SHA-256 lock."""
    root = knowledge_dir.resolve()
    if not root.is_dir():
        raise RagProvisionError("rag_knowledge_directory_missing")
    if not manifest_path.is_file():
        raise RagProvisionError("rag_knowledge_manifest_missing")

    expected: dict[str, str] = {}
    for line in manifest_path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        digest, separator, relative = line.partition("  ")
        if not separator or len(digest) != 64 or not relative:
            raise RagProvisionError("rag_knowledge_manifest_invalid")
        try:
            int(digest, 16)
        except ValueError as exc:
            raise RagProvisionError("rag_knowledge_manifest_invalid") from exc
        rel_path = Path(relative)
        if rel_path.is_absolute() or ".." in rel_path.parts:
            raise RagProvisionError("rag_knowledge_manifest_invalid")
        expected[rel_path.as_posix()] = digest.lower()

    actual = {
        path.relative_to(root).as_posix()
        for path in root.rglob("*.jsonl")
        if path.is_file()
    }
    if actual != set(expected):
        raise RagProvisionError("rag_knowledge_manifest_file_set_mismatch")

    for relative, expected_digest in expected.items():
        candidate = (root / relative).resolve()
        if not candidate.is_relative_to(root):
            raise RagProvisionError("rag_knowledge_manifest_invalid")
        digest = _sha256(candidate)
        if digest != expected_digest:
            raise RagProvisionError("rag_knowledge_manifest_hash_mismatch")


def provision_rag(
    *, knowledge_dir: Path, manifest_path: Path, model_name: str, model_revision: str
) -> dict[str, object]:
    """Verify pins then populate pgvector through the gateway authority path."""
    from rag_mcp.pgvector_seed import seed_knowledge_from_dir
    from rag_mcp.utils import CANONICAL_MODEL_NAME, CANONICAL_MODEL_REVISION

    if model_name != CANONICAL_MODEL_NAME or model_revision != CANONICAL_MODEL_REVISION:
        raise RagProvisionError("rag_model_pin_mismatch")
    dsn = os.environ.get("SIFT_CONTROL_PLANE_DSN", "").strip()
    if not dsn:
        raise RagProvisionError("rag_control_plane_dsn_unavailable")

    verify_knowledge_manifest(knowledge_dir, manifest_path)
    # The shared loader reads this explicit revision.  This process is installer
    # authority, not a RAG MCP child, and the model's network policy is controlled
    # by HF_HUB_OFFLINE / TRANSFORMERS_OFFLINE from setup-rag.sh.
    os.environ["RAG_MODEL_REVISION"] = model_revision
    result = seed_knowledge_from_dir(
        dsn=dsn,
        knowledge_dir=knowledge_dir,
        embedding_mode="model",
        model_name=model_name,
    )
    if result.status != "ok":
        raise RagProvisionError("rag_pgvector_seed_failed")
    return result.public_dict()


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Provision the SIFT RAG core add-on")
    parser.add_argument("--knowledge-dir", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--model-name", required=True)
    parser.add_argument("--model-revision", required=True)
    args = parser.parse_args(argv)
    try:
        result = provision_rag(
            knowledge_dir=args.knowledge_dir,
            manifest_path=args.manifest,
            model_name=args.model_name,
            model_revision=args.model_revision,
        )
    except RagProvisionError as exc:
        print(json.dumps({"status": "error", "reason": str(exc)}))
        return 2
    except Exception:
        # Do not surface DSNs, filesystem internals, or model-provider errors in
        # an installer transcript.  The pack emits a stable remediation instead.
        print(json.dumps({"status": "error", "reason": "rag_pgvector_seed_failed"}))
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
