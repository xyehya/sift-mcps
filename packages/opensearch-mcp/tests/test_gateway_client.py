"""Tests for gateway REST client resilience."""

from __future__ import annotations

import json
import urllib.error
from unittest.mock import patch

from opensearch_mcp import gateway


class _Response:
    status = 200

    def __init__(self, body: dict):
        self._body = json.dumps(body).encode()

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def read(self):
        return self._body


def test_wait_for_gateway_returns_false_when_unreachable():
    with (
        patch("opensearch_mcp.gateway.load_gateway_config", return_value={"url": "http://gw"}),
        patch("opensearch_mcp.gateway.urllib.request.urlopen", side_effect=OSError("down")),
        patch("opensearch_mcp.gateway.time.monotonic", side_effect=[0, 1, 3]),
        patch("opensearch_mcp.gateway.time.sleep"),
    ):
        assert gateway.wait_for_gateway(timeout=2) is False


def test_call_tool_retries_on_503():
    err = urllib.error.HTTPError("http://gw", 503, "unavailable", hdrs=None, fp=None)
    response = _Response({"result": [{"text": "{\"ok\": true}"}]})

    with (
        patch(
            "opensearch_mcp.gateway.load_gateway_config",
            return_value={"url": "http://gw", "token": "", "tls": False},
        ),
        patch(
            "opensearch_mcp.gateway.urllib.request.urlopen",
            side_effect=[err, err, response],
        ) as mock_urlopen,
        patch("opensearch_mcp.gateway.time.sleep") as mock_sleep,
    ):
        assert gateway.call_tool("check_file", {"path": "C:\\Windows\\x.exe"}) == {"ok": True}

    assert mock_urlopen.call_count == 3
    assert [call.args[0] for call in mock_sleep.call_args_list] == [1, 2]
