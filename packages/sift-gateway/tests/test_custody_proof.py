from __future__ import annotations

from pathlib import Path

import pytest
import sift_gateway.portal_services as portal_services
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from sift_gateway.custody_proof import (
    CustodyProofError,
    load_signing_key,
    sign_bundle,
    verify_bundle,
)
from sift_gateway.portal_services import EvidenceAuthorityService, PortalServiceError


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
    for path in ("/tmp/evidence.bin", "/etc/passwd", r"C:\\evidence\\x", "../escape"):
        with pytest.raises(CustodyProofError):
            sign_bundle({"path": path}, key)
    with pytest.raises(CustodyProofError):
        sign_bundle({"secret": "never"}, key)
    bundle = sign_bundle(_payload(), key)
    with pytest.raises(CustodyProofError, match="unknown"):
        verify_bundle(bundle, trusted_keys={})
    with pytest.raises(CustodyProofError, match="registry_required"):
        verify_bundle(bundle)


def test_group_or_world_readable_key_fails_closed(tmp_path: Path):
    key = _key(tmp_path)
    path = tmp_path / "unsafe.pem"
    path.write_bytes(key.private_key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    ))
    path.chmod(0o644)
    with pytest.raises(CustodyProofError, match="unavailable"):
        load_signing_key(path)


def test_seal_service_finalizes_only_after_signature(monkeypatch, tmp_path: Path):
    class _Operation:
        def __init__(self, *_args):
            pass

        def execute(self, _command, *, examiner):
            assert examiner == "examiner"
            return {"operation_id": "operation-1", "operation_phase": "PENDING_SIGNATURE"}

    service = EvidenceAuthorityService("postgresql://service@localhost/sift")
    monkeypatch.setattr(service, "_scan_evidence", lambda _case: None)
    monkeypatch.setattr(service, "finalize_pending_signature", lambda *, operation_id: {
        "operation_id": operation_id, "key_id": "ed25519:sha256:" + "a" * 64, "signed": True
    })
    monkeypatch.setattr(portal_services, "SealCustodyOperation", _Operation)
    result = service.seal(
        case_id="case", file_specs=[{"path": "evidence/a.bin"}], reason="seal",
        idempotency_key="id", reauth_audit_event_id="reauth", actor={"principal_type": "user", "principal_id": "u"}, examiner="examiner",
    )
    assert result["operation_phase"] == "COMPLETED"
    assert result["signature_key_id"].startswith("ed25519:")


def test_signature_failure_never_returns_completed():
    service = EvidenceAuthorityService("postgresql://service@localhost/sift")
    service.finalize_pending_signature = lambda *, operation_id: (_ for _ in ()).throw(
        PortalServiceError("custody_signing_authority_unavailable", http_status=503)
    )
    with pytest.raises(PortalServiceError, match="unavailable"):
        service._finalize_custody_result({"operation_id": "pending", "operation_phase": "PENDING_SIGNATURE"})
