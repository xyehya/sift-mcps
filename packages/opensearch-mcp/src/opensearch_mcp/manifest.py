"""SHA-256 file hashing for forensic provenance."""

from __future__ import annotations

import hashlib
import logging
from pathlib import Path

logger = logging.getLogger(__name__)


def sha256_file(path: Path) -> str:
    """Compute SHA-256 of a file using 64KB chunks.

    Returns empty string when hashing is impossible (e.g. FUSE filesystems
    that return EOVERFLOW on large reads).  Hashing is a provenance
    feature, not a critical-path operation — the ingest must not crash on
    hash failures.
    """
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            while True:
                chunk = f.read(65536)
                if not chunk:
                    break
                h.update(chunk)
        return h.hexdigest()
    except OSError as exc:
        logger.warning(
            "Cannot hash %s (%s) — recording empty hash and continuing. "
            "The file may reside on a FUSE filesystem with large-file read "
            "limitations.",
            path, exc,
        )
        return ""
