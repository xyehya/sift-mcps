"""Fail-on-revert installer contract for the custody signing authority."""

from pathlib import Path
from types import SimpleNamespace

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from sift_gateway import custody_proof

ROOT = Path(__file__).resolve().parents[1]


def test_installer_provisions_fixed_service_only_custody_signing_authority() -> None:
    helper = (ROOT / "scripts" / "setup-custody-signing-authority.sh").read_text()
    installer = (ROOT / "install.sh").read_text()
    hardening = (ROOT / "lib" / "hardening.sh").read_text()

    assert 'KEY_PATH="$KEY_DIR/ed25519-private.pem"' in helper
    assert 'KEY_DIR="/etc/sift/custody"' in helper
    assert 'STATE_DIR=' not in helper
    assert 'install -d -o root -g "$SERVICE_USER" -m 0750 /etc/sift' in helper
    assert 'install -d -o root -g "$SERVICE_USER" -m 0750 "$KEY_DIR"' in helper
    assert 'os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW' in helper
    assert 'os.link(tmp, key_path, follow_symlinks=False)' in helper
    assert 'stat.S_IMODE(info.st_mode) != 0o640' in helper
    assert 'info.st_uid != 0 or info.st_gid != gid' in helper
    assert 'os.fchown(fd, 0, gid)' in helper
    assert 'Ed25519PrivateKey.generate()' in helper
    assert '"$PYTHON_BIN" - "$KEY_DIR" "$KEY_PATH" "$SERVICE_USER"' in helper
    assert 'provision_custody_signing_authority' in hardening
    assert installer.index('install_state_dirs') < installer.index('provision_custody_signing_authority')
    assert 'SIFT_CUSTODY_SIGNING_KEY_PATH' not in helper


def test_runtime_default_uses_root_owned_state_parent_not_service_writable_sift_home() -> None:
    proof = (ROOT / "packages" / "sift-gateway" / "src" / "sift_gateway" / "custody_proof.py").read_text()

    assert '_DEFAULT_KEY_PATH = "/etc/sift/custody/ed25519-private.pem"' in proof
    assert "/var/lib/sift/" not in proof
    assert 'grp.getgrnam("sift-service").gr_gid' in proof
    assert 'info.st_uid != 0 or info.st_gid != service_gid or mode != 0o640' in proof


def test_gateway_apparmor_can_only_read_the_fixed_custody_signing_authority() -> None:
    profile = (ROOT / "configs" / "apparmor" / "sift-gateway.template").read_text()

    for rule in (
        "/etc/                                      r,",
        "/etc/sift/                                 r,",
        "/etc/sift/custody/                         r,",
        "/etc/sift/custody/ed25519-private.pem      r,",
    ):
        assert rule in profile
    assert "/etc/sift/custody/**" not in profile
    assert "/etc/sift/custody/ed25519-private.pem      rw" not in profile


def test_installed_authority_requires_root_service_group_read_only_mode(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    key_path = tmp_path / "ed25519-private.pem"
    key_path.write_bytes(
        Ed25519PrivateKey.generate().private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    monkeypatch.setattr(custody_proof, "_DEFAULT_KEY_PATH", str(key_path))
    monkeypatch.setattr(custody_proof.grp, "getgrnam", lambda _name: SimpleNamespace(gr_gid=4242))

    def authority_stat(*_args, **_kwargs):
        return SimpleNamespace(st_mode=0o100640, st_uid=0, st_gid=4242)

    monkeypatch.setattr(custody_proof.os, "stat", authority_stat)
    assert custody_proof.load_signing_key().key_id.startswith("ed25519:sha256:")

    monkeypatch.setattr(
        custody_proof.os,
        "stat",
        lambda *_args, **_kwargs: SimpleNamespace(st_mode=0o100600, st_uid=0, st_gid=4242),
    )
    with pytest.raises(custody_proof.CustodyProofError, match="unavailable"):
        custody_proof.load_signing_key()
