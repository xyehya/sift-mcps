"""Fail-on-revert installer contract for the custody signing authority."""

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_installer_provisions_fixed_service_only_custody_signing_authority() -> None:
    helper = (ROOT / "scripts" / "setup-custody-signing-authority.sh").read_text()
    installer = (ROOT / "install.sh").read_text()
    hardening = (ROOT / "lib" / "hardening.sh").read_text()

    assert 'KEY_PATH="$KEY_DIR/ed25519-private.pem"' in helper
    assert 'KEY_DIR="/etc/sift/custody"' in helper
    assert 'STATE_DIR=' not in helper
    assert 'install -d -o root -g "$SERVICE_USER" -m 0750 "$KEY_DIR"' in helper
    assert 'os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW' in helper
    assert 'os.link(tmp, key_path, follow_symlinks=False)' in helper
    assert 'stat.S_IMODE(info.st_mode) != 0o600' in helper
    assert 'info.st_uid != uid or info.st_gid != gid' in helper
    assert 'Ed25519PrivateKey.generate()' in helper
    assert '"$PYTHON_BIN" - "$KEY_DIR" "$KEY_PATH" "$SERVICE_USER"' in helper
    assert 'provision_custody_signing_authority' in hardening
    assert installer.index('install_state_dirs') < installer.index('provision_custody_signing_authority')
    assert 'SIFT_CUSTODY_SIGNING_KEY_PATH' not in helper


def test_runtime_default_uses_root_owned_state_parent_not_service_writable_sift_home() -> None:
    proof = (ROOT / "packages" / "sift-gateway" / "src" / "sift_gateway" / "custody_proof.py").read_text()

    assert '_DEFAULT_KEY_PATH = "/etc/sift/custody/ed25519-private.pem"' in proof
    assert "/var/lib/sift/" not in proof
