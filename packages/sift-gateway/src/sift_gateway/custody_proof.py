"""Canonical signed custody proof bundles.

The database remains the custody authority.  This module deliberately owns only
canonical serialization, the installation-held Ed25519 signing key, and offline
verification; it never opens evidence bytes or turns an exported bundle into an
admission decision.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import stat
from dataclasses import dataclass
from pathlib import Path, PureWindowsPath
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

_FORMAT = "sift-custody-proof/v1"
_DEFAULT_KEY_PATH = "/var/lib/sift/.sift/custody/ed25519-private.pem"


class CustodyProofError(ValueError):
    """A deliberately path-free proof/signing failure."""


@dataclass(frozen=True)
class SigningKey:
    private_key: Ed25519PrivateKey
    key_id: str
    public_key_b64: str


def canonical_bytes(value: dict[str, Any]) -> bytes:
    """Return the only byte representation that is signed or verified."""
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode(
            "utf-8"
        )
    except (TypeError, ValueError) as exc:
        raise CustodyProofError("proof_canonicalization_failed") from exc


def _reject_unsafe(value: Any) -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str) or key.lower() in {
                "private_key", "secret", "password", "dsn", "token"
            }:
                raise CustodyProofError("proof_contains_forbidden_material")
            _reject_unsafe(item)
    elif isinstance(value, list):
        for item in value:
            _reject_unsafe(item)
    elif isinstance(value, str):
        if (
            ".." in value
            or Path(value).is_absolute()
            or PureWindowsPath(value).is_absolute()
            or (len(value) >= 2 and value[1] == ":")
        ):
            raise CustodyProofError("proof_contains_absolute_or_unsafe_path")
        if "-----BEGIN" in value or "postgres" in value.lower():
            raise CustodyProofError("proof_contains_forbidden_material")


def load_signing_key(path: str | os.PathLike[str] | None = None) -> SigningKey:
    """Load a service-only PEM key from a fixed, owner-restricted path.

    The path is deployment configuration only; it is never copied into a proof
    or error. Group/world-readable key files fail closed.
    """
    configured = path or os.environ.get("SIFT_CUSTODY_SIGNING_KEY_PATH") or _DEFAULT_KEY_PATH
    try:
        info = os.stat(configured, follow_symlinks=False)
        if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077:
            raise CustodyProofError("custody_signing_authority_unavailable")
        raw = Path(configured).read_bytes()
        private = serialization.load_pem_private_key(raw, password=None)
    except (OSError, ValueError, TypeError) as exc:
        raise CustodyProofError("custody_signing_authority_unavailable") from exc
    if not isinstance(private, Ed25519PrivateKey):
        raise CustodyProofError("custody_signing_authority_unavailable")
    public_raw = private.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    public_b64 = base64.b64encode(public_raw).decode("ascii")
    return SigningKey(
        private_key=private,
        key_id="ed25519:sha256:" + hashlib.sha256(public_raw).hexdigest(),
        public_key_b64=public_b64,
    )


def sign_bundle(payload: dict[str, Any], key: SigningKey) -> dict[str, Any]:
    """Produce a path-safe portable proof with detached Ed25519 material."""
    _reject_unsafe(payload)
    body = {"format": _FORMAT, "payload": payload}
    signature = key.private_key.sign(canonical_bytes(body))
    return {
        **body,
        "signature": {
            "algorithm": "Ed25519",
            "key_id": key.key_id,
            "public_key": key.public_key_b64,
            "value": base64.b64encode(signature).decode("ascii"),
        },
    }


def verify_bundle(bundle: dict[str, Any], *, trusted_keys: dict[str, str] | None = None) -> dict[str, Any]:
    """Offline verify a canonical bundle without filesystem or DB access."""
    try:
        if set(bundle) != {"format", "payload", "signature"} or bundle["format"] != _FORMAT:
            raise CustodyProofError("invalid_proof_bundle")
        payload, signature = bundle["payload"], bundle["signature"]
        if not isinstance(payload, dict) or not isinstance(signature, dict):
            raise CustodyProofError("invalid_proof_bundle")
        _reject_unsafe(payload)
        if set(signature) != {"algorithm", "key_id", "public_key", "value"}:
            raise CustodyProofError("invalid_proof_bundle")
        if signature["algorithm"] != "Ed25519" or not isinstance(signature["key_id"], str):
            raise CustodyProofError("invalid_proof_bundle")
        public_b64 = signature["public_key"]
        if trusted_keys is None:
            raise CustodyProofError("trusted_custody_key_registry_required")
        expected = trusted_keys.get(signature["key_id"])
        if expected is None or expected != public_b64:
            raise CustodyProofError("unknown_custody_signing_key")
        public_raw = base64.b64decode(public_b64, validate=True)
        if len(public_raw) != 32:
            raise CustodyProofError("invalid_proof_bundle")
        derived = "ed25519:sha256:" + hashlib.sha256(public_raw).hexdigest()
        if derived != signature["key_id"]:
            raise CustodyProofError("invalid_proof_bundle")
        sig = base64.b64decode(signature["value"], validate=True)
        Ed25519PublicKey.from_public_bytes(public_raw).verify(
            sig, canonical_bytes({"format": _FORMAT, "payload": payload})
        )
    except CustodyProofError:
        raise
    except (InvalidSignature, KeyError, TypeError, ValueError) as exc:
        raise CustodyProofError("invalid_proof_bundle") from exc
    return {"valid": True, "key_id": signature["key_id"], "payload": payload}
