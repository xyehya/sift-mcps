"""SEC-15 fail-on-revert tests for OpenCTI transport and credential redaction."""

from __future__ import annotations

import logging
import sys
from types import ModuleType

import pytest
from opencti_mcp.client import OpenCTIClient
from opencti_mcp.config import Config, _validate_url
from opencti_mcp.errors import ConfigurationError
from sift_common.env import SecretStr


@pytest.mark.parametrize(
    "url",
    [
        "http://localhost:8080",
        "http://127.0.0.1:8080",
        "http://127.99.88.77:8080",
        "http://[::1]:8080",
    ],
)
def test_http_loopback_is_allowed(url: str, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("OPENCTI_INSECURE_HTTP_REMOTE", raising=False)
    assert _validate_url(url) == url


@pytest.mark.parametrize("url", ["http://192.168.122.81:8080", "http://198.51.100.20:8080"])
def test_non_loopback_http_is_denied_without_explicit_override(
    url: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("OPENCTI_INSECURE_HTTP_REMOTE", raising=False)

    with pytest.raises(ConfigurationError) as exc_info:
        _validate_url(url)

    assert url not in str(exc_info.value)
    assert "HTTPS" in str(exc_info.value)


def test_non_loopback_http_stays_denied_even_if_a_stale_override_is_present(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    remote_url = "http://192.168.122.81:8080"
    monkeypatch.setenv("OPENCTI_INSECURE_HTTP_REMOTE", "1")
    with pytest.raises(ConfigurationError):
        _validate_url(remote_url)


def test_url_userinfo_is_rejected_without_echoing_its_value() -> None:
    endpoint = "https://operator:credential@private-opencti.example:8443"

    with pytest.raises(ConfigurationError) as exc_info:
        _validate_url(endpoint)

    assert endpoint not in str(exc_info.value)


def test_https_is_allowed_without_override(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("OPENCTI_INSECURE_HTTP_REMOTE", raising=False)
    assert _validate_url("https://192.168.122.81:8443/") == "https://192.168.122.81:8443"


def test_config_and_startup_diagnostics_do_not_expose_endpoint(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    endpoint = "https://private-opencti.example:8443"
    config = Config(opencti_url=endpoint, opencti_token=SecretStr("test-token"))
    assert endpoint not in repr(config)

    client = OpenCTIClient(config)
    monkeypatch.setattr(client, "_connect_probe", lambda: (_ for _ in ()).throw(OSError("offline")))
    validation = client.validate_startup()
    assert endpoint not in " ".join(validation["errors"])

    monkeypatch.setattr(client, "connect", lambda: object())
    monkeypatch.setattr(client, "_get_opencti_version", lambda _client: {"version": "7.0"})
    info = client.get_server_info()
    assert "url" not in info
    assert info["endpoint_scheme"] == "https"


def test_connect_error_never_logs_the_configured_endpoint(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    endpoint = "https://private-opencti.example:8443"

    class FailingClient:
        def __init__(self, *_args: object, **_kwargs: object) -> None:
            raise OSError(f"connection failed for {endpoint}")

    fake_pycti = ModuleType("pycti")
    fake_pycti.OpenCTIApiClient = FailingClient  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "pycti", fake_pycti)
    client = OpenCTIClient(Config(opencti_url=endpoint, opencti_token=SecretStr("test-token")))

    caplog.set_level(logging.ERROR, logger="opencti_mcp.client")
    with pytest.raises(Exception) as exc_info:
        client.connect()

    assert endpoint not in caplog.text
    assert endpoint not in str(exc_info.value)
    assert caplog.records[-1].__dict__["error_type"] == "OSError"
