"""Tests for the packaged OpenSearch Docker topology."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml

_REPO_ROOT = Path(__file__).parent.parent
_DOCKER_COMPOSE = _REPO_ROOT / "docker" / "docker-compose.yml"
_TEMPLATE_PATH = _REPO_ROOT / "src" / "opensearch_mcp" / "mappings" / "evtx_ecs_template.json"


# ---------------------------------------------------------------------------
# Docker Compose
# ---------------------------------------------------------------------------


class TestDockerCompose:
    @pytest.fixture
    def compose(self):
        return yaml.safe_load(_DOCKER_COMPOSE.read_text())

    def test_heap_4gb(self, compose):
        """Security Analytics needs 4GB heap minimum."""
        env = compose["services"]["opensearch"]["environment"]
        java_opts = [e for e in env if "JAVA_OPTS" in e][0]
        assert "-Xms4g" in java_opts
        assert "-Xmx4g" in java_opts

    def test_heap_xms_equals_xmx(self, compose):
        """Xms must equal Xmx for predictable performance."""
        env = compose["services"]["opensearch"]["environment"]
        java_opts = [e for e in env if "JAVA_OPTS" in e][0]
        # Extract values
        xms = java_opts.split("-Xms")[1].split(" ")[0].split("-")[0].strip()
        xmx = java_opts.split("-Xmx")[1].split(" ")[0].strip()
        assert xms == xmx

    def test_mem_limit_exceeds_heap(self, compose):
        """Container mem_limit must exceed heap to allow JVM native memory."""
        mem = compose["services"]["opensearch"]["mem_limit"]
        # Parse mem_limit (e.g., "6g")
        if isinstance(mem, str):
            mem_gb = int(mem.rstrip("gG"))
        else:
            mem_gb = mem / (1024**3)
        assert mem_gb >= 6  # 4g heap + 2g overhead

    def test_single_node_discovery(self, compose):
        env = compose["services"]["opensearch"]["environment"]
        assert "discovery.type=single-node" in env

    def test_port_localhost_only(self, compose):
        ports = compose["services"]["opensearch"]["ports"]
        for port in ports:
            assert port.startswith("127.0.0.1:"), f"Port {port} not bound to localhost"


# ---------------------------------------------------------------------------
# Template + Pipeline coherence
# ---------------------------------------------------------------------------


class TestTemplateCoherence:
    def test_geo_fields_in_template(self):
        """All GeoIP output fields must have explicit mappings to avoid
        text+keyword default dynamic mapping."""
        template = json.loads(_TEMPLATE_PATH.read_text())
        props = template["template"]["mappings"]["properties"]
        expected_geo_fields = [
            "source.geo.country_name",
            "source.geo.city_name",
            "source.geo.continent_name",
            "source.geo.region_name",
            "source.geo.location",
        ]
        for field in expected_geo_fields:
            assert field in props, f"Missing GeoIP field mapping: {field}"
