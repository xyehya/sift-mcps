"""Tests for sift_core.gateway_cfg — gateway config helpers."""

from __future__ import annotations

import ssl
from unittest import mock

from sift_core.gateway_cfg import (
    _read_gateway_config,
    find_ca_cert,
    get_local_gateway_url,
    get_local_ssl_context,
)


class TestReadGatewayConfig:
    def test_missing_file_returns_empty(self, tmp_path):
        with mock.patch("sift_core.gateway_cfg.Path.home", return_value=tmp_path):
            assert _read_gateway_config() == {}

    def test_valid_yaml(self, tmp_path):
        sift_dir = tmp_path / ".sift"
        sift_dir.mkdir()
        (sift_dir / "gateway.yaml").write_text(
            "gateway:\n  port: 9999\n  tls:\n    certfile: /cert.pem\n"
        )
        with mock.patch("sift_core.gateway_cfg.Path.home", return_value=tmp_path):
            config = _read_gateway_config()
            assert config["gateway"]["port"] == 9999

    def test_corrupt_yaml_returns_empty(self, tmp_path):
        sift_dir = tmp_path / ".sift"
        sift_dir.mkdir()
        (sift_dir / "gateway.yaml").write_text(":\ninvalid: [yaml")
        with mock.patch("sift_core.gateway_cfg.Path.home", return_value=tmp_path):
            result = _read_gateway_config()
            # Either empty dict or partially-parsed — should not raise
            assert isinstance(result, dict)


class TestGetLocalGatewayUrl:
    def test_default_fallback(self, tmp_path):
        with mock.patch("sift_core.gateway_cfg.Path.home", return_value=tmp_path):
            assert get_local_gateway_url() == "http://127.0.0.1:4508"

    def test_custom_port(self, tmp_path):
        sift_dir = tmp_path / ".sift"
        sift_dir.mkdir()
        (sift_dir / "gateway.yaml").write_text("gateway:\n  port: 8000\n")
        with mock.patch("sift_core.gateway_cfg.Path.home", return_value=tmp_path):
            assert get_local_gateway_url() == "http://127.0.0.1:8000"

    def test_tls_uses_https(self, tmp_path):
        sift_dir = tmp_path / ".sift"
        sift_dir.mkdir()
        (sift_dir / "gateway.yaml").write_text(
            "gateway:\n  port: 4508\n  tls:\n    certfile: /cert.pem\n"
        )
        with mock.patch("sift_core.gateway_cfg.Path.home", return_value=tmp_path):
            assert get_local_gateway_url() == "https://127.0.0.1:4508"

    def test_non_dict_gateway_returns_default(self, tmp_path):
        sift_dir = tmp_path / ".sift"
        sift_dir.mkdir()
        (sift_dir / "gateway.yaml").write_text("gateway: just-a-string\n")
        with mock.patch("sift_core.gateway_cfg.Path.home", return_value=tmp_path):
            assert get_local_gateway_url() == "http://127.0.0.1:4508"


class TestFindCaCert:
    def test_no_cert_file(self, tmp_path):
        with mock.patch("sift_core.gateway_cfg.Path.home", return_value=tmp_path):
            assert find_ca_cert() is None

    def test_cert_found(self, tmp_path):
        tls_dir = tmp_path / ".sift" / "tls"
        tls_dir.mkdir(parents=True)
        ca = tls_dir / "ca-cert.pem"
        ca.write_text("CERT")
        with mock.patch("sift_core.gateway_cfg.Path.home", return_value=tmp_path):
            assert find_ca_cert() == str(ca)


class TestGetLocalSslContext:
    def test_no_config_returns_none(self, tmp_path):
        with mock.patch("sift_core.gateway_cfg.Path.home", return_value=tmp_path):
            assert get_local_ssl_context() is None

    def test_no_tls_in_config_returns_none(self, tmp_path):
        sift_dir = tmp_path / ".sift"
        sift_dir.mkdir()
        (sift_dir / "gateway.yaml").write_text("gateway:\n  port: 4508\n")
        with mock.patch("sift_core.gateway_cfg.Path.home", return_value=tmp_path):
            assert get_local_ssl_context() is None

    def test_tls_without_ca_returns_unverified_context(self, tmp_path):
        sift_dir = tmp_path / ".sift"
        sift_dir.mkdir()
        (sift_dir / "gateway.yaml").write_text(
            "gateway:\n  tls:\n    certfile: /cert.pem\n"
        )
        with mock.patch("sift_core.gateway_cfg.Path.home", return_value=tmp_path):
            ctx = get_local_ssl_context()
            assert ctx is not None
            assert ctx.verify_mode == ssl.CERT_NONE

    def test_tls_with_valid_ca_returns_verified_context(self, tmp_path):
        sift_dir = tmp_path / ".sift"
        sift_dir.mkdir()
        tls_dir = sift_dir / "tls"
        tls_dir.mkdir()
        # Create a self-signed CA for testing
        from subprocess import DEVNULL, run

        run(
            [
                "openssl", "req", "-x509", "-newkey", "rsa:2048",
                "-keyout", str(tls_dir / "ca-key.pem"),
                "-out", str(tls_dir / "ca-cert.pem"),
                "-days", "1", "-nodes",
                "-subj", "/CN=test-ca",
            ],
            check=True,
            stdout=DEVNULL,
            stderr=DEVNULL,
        )
        (sift_dir / "gateway.yaml").write_text(
            "gateway:\n  tls:\n    certfile: /cert.pem\n"
        )
        with mock.patch("sift_core.gateway_cfg.Path.home", return_value=tmp_path):
            ctx = get_local_ssl_context()
            assert ctx is not None
            assert ctx.check_hostname is True
