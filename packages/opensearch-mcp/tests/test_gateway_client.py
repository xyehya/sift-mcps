"""Tests for gateway REST client resilience."""

from __future__ import annotations

from unittest.mock import patch

from opensearch_mcp import gateway


def test_wait_for_gateway_returns_false_when_unreachable():
    with (
        patch("opensearch_mcp.gateway.load_gateway_config", return_value={"url": "http://gw"}),
        patch("opensearch_mcp.gateway.urllib.request.urlopen", side_effect=OSError("down")),
        patch("opensearch_mcp.gateway.time.monotonic", side_effect=[0, 1, 3]),
        patch("opensearch_mcp.gateway.time.sleep"),
    ):
        assert gateway.wait_for_gateway(timeout=2) is False
