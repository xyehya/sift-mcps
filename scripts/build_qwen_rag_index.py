#!/usr/bin/env python3
"""Create a portable, provenance-rich Qwen dense-vector RAG snapshot.

This is an offline artifact builder: it never connects to a database and does
not expose a service. It accepts only local JSONL corpus directories, writes a
new output directory, and pins the Hugging Face model revision supplied by the
operator. The resulting records.jsonl plus embeddings.f32.npy can be imported
by a gateway-owned pgvector migration without giving an MCP child DB access.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

MAX_INPUT_FILE_BYTES = 64 * 1024 * 1024
MAX_TEXT_CHARS = 2 * 1024 * 1024
EXPECTED_RECORDS = 22_268
MODEL = "Qwen/Qwen3-Embedding-0.6B"
DIMENSION = 1024
DEFAULT_MAX_LENGTH = 2048


@dataclass(frozen=True)
class InputFile:
    relative_path: str
    sha256: str
    records: int


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sources-dir", type=Path, required=True)
    parser.add_argument("--knowledge-dir", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--model", default=MODEL)
    parser.add_argument("--revision", required=True)
    parser.add_argument("--batch-size", type=int, default=16)
    parser.add_argument("--max-length", type=int, default=DEFAULT_MAX_LENGTH)
    parser.add_argument("--expected-records", type=int, default=EXPECTED_RECORDS)
    parser.add_argument("--device", choices=("cuda", "cpu"), default="cuda")
    return parser.parse_args()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def jsonl_files(root: Path) -> list[Path]:
    root = root.resolve(strict=True)
    files: list[Path] = []
    for path in sorted(root.rglob("*.jsonl")):
        resolved = path.resolve(strict=True)
        if root not in resolved.parents:
            raise ValueError(f"input escaped corpus root: {path}")
        if resolved.stat().st_size > MAX_INPUT_FILE_BYTES:
            raise ValueError(f"input exceeds {MAX_INPUT_FILE_BYTES} bytes: {path.name}")
        files.append(resolved)
    if not files:
        raise ValueError(f"no JSONL files under {root}")
    return files


def load_records(root: Path, prefix: str) -> tuple[list[dict[str, Any]], list[InputFile]]:
    root = root.resolve(strict=True)
    records: list[dict[str, Any]] = []
    inputs: list[InputFile] = []
    for path in jsonl_files(root):
        before = len(records)
        rel = path.relative_to(root).as_posix()
        with path.open(encoding="utf-8") as handle:
            for line_number, line in enumerate(handle, start=1):
                if not line.strip():
                    continue
                raw = json.loads(line)
                if not isinstance(raw, dict):
                    raise ValueError(f"{prefix}/{rel}:{line_number}: record must be an object")
                text = str(raw.get("text") or "").strip()
                if not text or len(text) > MAX_TEXT_CHARS:
                    raise ValueError(f"{prefix}/{rel}:{line_number}: invalid text length")
                metadata = raw.get("metadata")
                if metadata is None:
                    metadata = {}
                if not isinstance(metadata, dict):
                    raise ValueError(f"{prefix}/{rel}:{line_number}: metadata must be an object")
                upstream_id = str(raw.get("id") or f"{prefix}:{rel}:{line_number}").strip()
                record_id = hashlib.sha256(
                    f"qwen-rag-v1\0{prefix}\0{rel}\0{upstream_id}".encode()
                ).hexdigest()
                records.append(
                    {
                        "id": record_id,
                        "upstream_id": upstream_id,
                        "source_file": f"{prefix}/{rel}",
                        "text": text,
                        "metadata": metadata,
                    }
                )
        inputs.append(InputFile(rel, sha256_file(path), len(records) - before))
    return records, inputs


def last_token_pool(last_hidden_states, attention_mask):
    import torch  # pyright: ignore[reportMissingImports]

    left_padding = bool((attention_mask[:, -1].sum() == attention_mask.shape[0]).item())
    if left_padding:
        return last_hidden_states[:, -1]
    sequence_lengths = attention_mask.sum(dim=1) - 1
    return last_hidden_states[
        torch.arange(last_hidden_states.shape[0], device=last_hidden_states.device),
        sequence_lengths,
    ]


def build_embeddings(
    records: list[dict[str, Any]], *, model_name: str, revision: str, batch_size: int,
    max_length: int, device: str
):
    import numpy as np  # pyright: ignore[reportMissingImports]
    import torch  # pyright: ignore[reportMissingImports]
    from transformers import (  # pyright: ignore[reportMissingImports]
        AutoModel,
        AutoTokenizer,
    )

    if batch_size < 1 or batch_size > 128:
        raise ValueError("batch-size must be 1..128")
    if max_length < 32 or max_length > 8192:
        raise ValueError("max-length must be 32..8192")
    if device == "cuda" and not torch.cuda.is_available():
        raise RuntimeError("CUDA requested but unavailable")
    tokenizer = AutoTokenizer.from_pretrained(model_name, revision=revision, padding_side="left")
    model = AutoModel.from_pretrained(
        model_name,
        revision=revision,
        torch_dtype=torch.float16 if device == "cuda" else torch.float32,
    ).to(device).eval()
    rows: list[Any] = []
    with torch.inference_mode():
        for start in range(0, len(records), batch_size):
            batch = [row["text"] for row in records[start : start + batch_size]]
            encoded = tokenizer(
                batch,
                padding=True,
                truncation=True,
                max_length=max_length,
                return_tensors="pt",
            ).to(device)
            output = model(**encoded)
            embedding = last_token_pool(output.last_hidden_state, encoded["attention_mask"])
            embedding = torch.nn.functional.normalize(embedding, p=2, dim=1)
            if embedding.shape[1] != DIMENSION:
                raise RuntimeError(f"unexpected embedding dimension: {embedding.shape[1]}")
            rows.append(embedding.float().cpu().numpy())
            print(f"embedded {min(start + len(batch), len(records))}/{len(records)}", flush=True)
    return np.concatenate(rows, axis=0)


def write_artifact(
    output_dir: Path, records: list[dict[str, Any]], inputs: list[InputFile], embeddings,
    args: argparse.Namespace
) -> None:
    import numpy as np  # pyright: ignore[reportMissingImports]

    output_dir = output_dir.resolve()
    if output_dir.exists():
        raise FileExistsError(f"refusing to overwrite output directory: {output_dir}")
    output_dir.mkdir(parents=True, mode=0o750)
    records_path = output_dir / "records.jsonl"
    with records_path.open("x", encoding="utf-8") as handle:
        for index, record in enumerate(records):
            payload = {**record, "embedding_row": index}
            handle.write(json.dumps(payload, ensure_ascii=False, separators=(",", ":")) + "\n")
    embeddings_path = output_dir / "embeddings.f32.npy"
    with embeddings_path.open("xb") as handle:
        np.save(handle, embeddings.astype(np.float32, copy=False), allow_pickle=False)
    manifest = {
        "format": "sift-rag-qwen-portable-v1",
        "model": args.model,
        "model_revision": args.revision,
        "embedding_dimension": DIMENSION,
        "distance": "cosine",
        "document_transform": "raw-source-text-v1",
        "query_instruction_required": True,
        "query_instruction": (
            "Given a digital-forensics and incident-response query, retrieve "
            "the most relevant authoritative reference passages."
        ),
        "record_count": len(records),
        "input_files": [asdict(item) for item in inputs],
        "artifacts": {
            "records.jsonl": sha256_file(records_path),
            "embeddings.f32.npy": sha256_file(embeddings_path),
        },
    }
    (output_dir / "manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


def main() -> int:
    args = parse_args()
    if args.output_dir.exists():
        raise SystemExit(f"refusing to overwrite output directory: {args.output_dir}")
    sources, source_inputs = load_records(args.sources_dir, "sources")
    knowledge, knowledge_inputs = load_records(args.knowledge_dir, "knowledge")
    records = sources + knowledge
    if len(records) != args.expected_records:
        raise SystemExit(
            f"unexpected corpus size: {len(records)} (expected {args.expected_records})"
        )
    if len({record["id"] for record in records}) != len(records):
        raise SystemExit("stable record identifier collision")
    embeddings = build_embeddings(
        records,
        model_name=args.model,
        revision=args.revision,
        batch_size=args.batch_size,
        max_length=args.max_length,
        device=args.device,
    )
    write_artifact(args.output_dir, records, source_inputs + knowledge_inputs, embeddings, args)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
