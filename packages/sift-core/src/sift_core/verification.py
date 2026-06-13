"""HMAC verification ledger for approved findings and timeline events.

Ledger lives at /var/lib/sift/verification/{case-id}.jsonl.
This path is outside any user's home directory and is unreachable by the
Claude Code sandbox from any CWD.

CL3b (B-MVP-017): the password-keyed file-HMAC re-auth helpers that lived here
(``derive_hmac_key`` / ``verify_items`` / ``rehmac_entries`` / ``read_ledger`` /
``copy_ledger_to_case``) were part of the dead file-HMAC re-auth plane and had
zero source callers after CL3a moved sensitive-action re-auth to Supabase. They
were deleted. What remains is the file-authority COMMIT ledger *writer*
(``write_ledger_entry`` + ``compute_hmac``), still called from the case-dashboard
``_apply_delta`` path — that ledger is OUT of scope and is intentionally
untouched.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
from pathlib import Path

VERIFICATION_DIR = Path(os.environ.get("SIFT_VERIFICATION_DIR", "/var/lib/sift/verification"))


def _validate_case_id(case_id: str) -> None:
    if not case_id:
        raise ValueError("Case ID cannot be empty")
    if ".." in case_id or "/" in case_id or "\\" in case_id:
        raise ValueError(f"Invalid case ID (path traversal characters): {case_id}")


def compute_hmac(derived_key: bytes, description: str) -> str:
    return hmac.new(
        derived_key, description.encode("utf-8"), hashlib.sha256
    ).hexdigest()


def write_ledger_entry(case_id: str, entry: dict) -> None:
    _validate_case_id(case_id)
    VERIFICATION_DIR.mkdir(parents=True, exist_ok=True, mode=0o700)
    path = VERIFICATION_DIR / f"{case_id}.jsonl"
    with open(path, "a") as f:
        f.write(json.dumps(entry) + "\n")
        f.flush()
        os.fsync(f.fileno())
    os.chmod(path, 0o600)
