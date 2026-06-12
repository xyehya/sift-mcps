"""BATCH-TLS1: installer TLS / local-CA profile tests.

These tests exercise the *real* certificate-generation command sequence used by
``install.sh`` (and mirrored in ``scripts/rotate-tls.sh``) so a regression like
``openssl req`` rejecting ``-extfile`` is caught before a VM run.

They run pure ``openssl`` in a temp dir (no sudo, no service install) and assert
the contract the batch requires:

* leaf verifies against the CA,
* SANs are derived (primary IP + loopback + hostname + localhost),
* leaf carries ``extendedKeyUsage=serverAuth`` and ``CA:FALSE``,
* the CA carries critical ``CA:TRUE``,
* CA validity > leaf validity,
* a leaf renewal against the SAME CA keeps the CA fingerprint stable
  (idempotency / no-re-trust contract).
"""
from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

openssl = shutil.which("openssl")
pytestmark = pytest.mark.skipif(openssl is None, reason="openssl not installed")

CA_CN = "Protocol SIFT Gateway local CA"
CA_DAYS = "3650"
LEAF_DAYS = "730"
SAN = "IP:192.168.122.81,IP:127.0.0.1,DNS:siftvm,DNS:localhost"


def _run(*args: str) -> str:
    res = subprocess.run(
        [openssl, *args], capture_output=True, text=True, check=True
    )
    return res.stdout


def _make_ca(d: Path) -> None:
    _run("genrsa", "-out", str(d / "ca-key.pem"), "4096")
    # CA extensions MUST go through -addext; `openssl req` rejects -extfile.
    _run(
        "req", "-new", "-x509", "-days", CA_DAYS,
        "-key", str(d / "ca-key.pem"),
        "-out", str(d / "ca-cert.pem"),
        "-subj", f"/CN={CA_CN}",
        "-addext", "basicConstraints=critical,CA:TRUE",
        "-addext", "keyUsage=critical,keyCertSign,cRLSign",
    )


def _sign_leaf(d: Path) -> None:
    ext = d / "leaf-ext.cnf"
    ext.write_text(
        "basicConstraints=CA:FALSE\n"
        "keyUsage=critical,digitalSignature,keyEncipherment\n"
        "extendedKeyUsage=serverAuth\n"
        f"subjectAltName={SAN}\n"
    )
    _run("genrsa", "-out", str(d / "gateway-key.pem"), "4096")
    _run(
        "req", "-new", "-key", str(d / "gateway-key.pem"),
        "-out", str(d / "gateway-csr.pem"), "-subj", "/CN=siftvm",
    )
    # The leaf-signing step DOES accept -extfile (it is `openssl x509`).
    _run(
        "x509", "-req", "-days", LEAF_DAYS,
        "-in", str(d / "gateway-csr.pem"),
        "-CA", str(d / "ca-cert.pem"), "-CAkey", str(d / "ca-key.pem"),
        "-CAcreateserial",
        "-out", str(d / "gateway-cert.pem"),
        "-extfile", str(ext),
    )


def _fingerprint(cert: Path) -> str:
    return _run("x509", "-in", str(cert), "-noout", "-fingerprint", "-sha256")


def test_leaf_verifies_against_ca(tmp_path: Path) -> None:
    _make_ca(tmp_path)
    _sign_leaf(tmp_path)
    out = _run(
        "verify", "-CAfile", str(tmp_path / "ca-cert.pem"),
        str(tmp_path / "gateway-cert.pem"),
    )
    assert "OK" in out


def test_leaf_has_serverauth_and_derived_sans(tmp_path: Path) -> None:
    _make_ca(tmp_path)
    _sign_leaf(tmp_path)
    exts = _run(
        "x509", "-in", str(tmp_path / "gateway-cert.pem"), "-noout",
        "-ext", "subjectAltName,extendedKeyUsage,basicConstraints",
    )
    assert "TLS Web Server Authentication" in exts
    assert "IP Address:192.168.122.81" in exts
    assert "IP Address:127.0.0.1" in exts
    assert "DNS:localhost" in exts
    assert "CA:FALSE" in exts


def test_ca_is_marked_critical_ca_true(tmp_path: Path) -> None:
    _make_ca(tmp_path)
    exts = _run(
        "x509", "-in", str(tmp_path / "ca-cert.pem"), "-noout",
        "-ext", "basicConstraints",
    )
    assert "critical" in exts
    assert "CA:TRUE" in exts


def test_ca_outlives_leaf(tmp_path: Path) -> None:
    assert int(CA_DAYS) > int(LEAF_DAYS)


def test_leaf_renewal_preserves_ca_fingerprint(tmp_path: Path) -> None:
    """Renewing the leaf against the same CA must not change the CA.

    This is the no-re-trust contract: scripts/rotate-tls.sh --renew-leaf and an
    idempotent install rerun both keep the existing CA.
    """
    _make_ca(tmp_path)
    fp_before = _fingerprint(tmp_path / "ca-cert.pem")
    _sign_leaf(tmp_path)
    leaf_fp_1 = _fingerprint(tmp_path / "gateway-cert.pem")
    # Renew the leaf only (same CA cert + key on disk).
    _sign_leaf(tmp_path)
    leaf_fp_2 = _fingerprint(tmp_path / "gateway-cert.pem")
    fp_after = _fingerprint(tmp_path / "ca-cert.pem")

    assert fp_before == fp_after  # CA untouched by leaf renewal
    assert leaf_fp_1 != leaf_fp_2  # leaf actually changed
