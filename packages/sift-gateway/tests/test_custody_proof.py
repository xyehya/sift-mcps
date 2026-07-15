from __future__ import annotations

from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from sift_gateway.custody_proof import (
    CustodyProofError,
    load_signing_key,
    sign_bundle,
    verify_bundle,
)


def _key(tmp_path: Path):
    path = tmp_path / "custody.pem"
    path.write_bytes(
        Ed25519PrivateKey.generate().private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    path.chmod(0o600)
    return load_signing_key(path)


def _payload():
    return {"case_id": "case-opaque", "events": [{"seq": 1, "event_hash": "sha256:x"}]}


def test_signed_bundle_round_trips_offline(tmp_path: Path):
    key = _key(tmp_path)
    bundle = sign_bundle(_payload(), key)
    assert verify_bundle(bundle, trusted_keys={key.key_id: key.public_key_b64})["valid"] is True


@pytest.mark.parametrize("field", ["payload", "signature"])
def test_tampered_or_unknown_bundle_is_rejected(tmp_path: Path, field: str):
    key = _key(tmp_path)
    bundle = sign_bundle(_payload(), key)
    if field == "payload":
        bundle["payload"]["case_id"] = "changed"
    else:
        bundle["signature"]["value"] = "AA=="
    with pytest.raises(CustodyProofError):
        verify_bundle(bundle, trusted_keys={key.key_id: key.public_key_b64})


def test_unknown_key_absolute_path_and_secret_are_rejected(tmp_path: Path):
    key = _key(tmp_path)
    with pytest.raises(CustodyProofError):
        sign_bundle({"path": "/var/lib/sift/evidence"}, key)
    with pytest.raises(CustodyProofError):
        sign_bundle({"secret": "never"}, key)
    bundle = sign_bundle(_payload(), key)
    with pytest.raises(CustodyProofError, match="unknown"):
        verify_bundle(bundle, trusted_keys={})


def test_group_or_world_readable_key_fails_closed(tmp_path: Path):
    key = _key(tmp_path)
    path = tmp_path / "unsafe.pem"
    path.write_bytes(key.private_key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    ))
    path.chmod(0o644)
    with pytest.raises(CustodyProofError, match="unavailable"):
        load_signing_key(path)
