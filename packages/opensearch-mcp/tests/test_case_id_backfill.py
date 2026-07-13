"""P3.2 derived ``sift.case_id`` mapping and backfill contracts."""

from __future__ import annotations

from unittest.mock import MagicMock

from opensearch_mcp.case_id_backfill import plan_or_apply_case_id_backfill
from opensearch_mcp.case_scoped import case_id_term_filter
from opensearch_mcp.mappings import install_all_templates


def _mapping(field_type: str | None) -> dict:
    props = {} if field_type is None else {"sift.case_id": {"type": field_type}}
    return {"case-foo-evtx-host": {"mappings": {"properties": props}}}


def test_term_filter_uses_normalized_index_key_not_gateway_uuid(tmp_path):
    case_dir = tmp_path / "case-Foo"
    case_dir.mkdir()

    clause = case_id_term_filter(
        "674425ae-78ea-4c9c-9a14-3c9d0b6f900c", str(case_dir)
    )

    assert clause == {"term": {"sift.case_id": "foo"}}


def test_term_filter_without_resolvable_case_is_omitted(monkeypatch):
    monkeypatch.setattr(
        "opensearch_mcp.case_scoped.resolve_active_case_prefix", lambda *_args: None
    )
    assert case_id_term_filter() is None


def test_component_is_plain_and_all_non_evtx_templates_compose_it():
    client = MagicMock()
    result = install_all_templates(client)

    component_bodies = {
        call.kwargs["name"]: call.kwargs["body"]
        for call in client.cluster.put_component_template.call_args_list
    }
    assert "sift-case-metadata" in component_bodies
    assert "composed_of" not in component_bodies["sift-case-metadata"]
    assert result["components"]["failed"] == []

    for call in client.indices.put_index_template.call_args_list:
        assert "sift-case-metadata" in call.kwargs["body"].get("composed_of", [])


def test_backfill_plans_missing_mapping_without_writes():
    client = MagicMock()
    client.indices.get_mapping.return_value = _mapping(None)
    client.count.side_effect = [{"count": 4}, {"count": 0}, {"count": 4}]

    result = plan_or_apply_case_id_backfill(client, "case-foo")

    assert result["status"] == "planned"
    assert result["index_pattern"] == "case-foo-*"
    assert result["indices"] == [
        {
            "index": "case-foo-evtx-host",
            "mapping_type": None,
            "before_count": 4,
            "status": "ready",
        }
    ]
    client.indices.put_mapping.assert_not_called()
    client.update_by_query.assert_not_called()


def test_backfill_applies_keyword_mapping_and_proves_count_agreement():
    client = MagicMock()
    client.indices.get_mapping.return_value = _mapping(None)
    client.count.side_effect = [{"count": 4}, {"count": 4}]
    client.update_by_query.return_value = {"updated": 4}

    result = plan_or_apply_case_id_backfill(client, "case-foo", apply=True)

    assert result["status"] == "migrated"
    client.indices.put_mapping.assert_called_once_with(
        index="case-foo-evtx-host",
        body={"properties": {"sift.case_id": {"type": "keyword", "ignore_above": 1024}}},
    )
    update_body = client.update_by_query.call_args.kwargs["body"]
    assert update_body["script"]["params"] == {"case_id": "foo"}
    assert result["indices"][0]["term_count"] == result["indices"][0]["before_count"] == 4


def test_non_keyword_mapping_requires_reindex_without_writes():
    client = MagicMock()
    client.indices.get_mapping.return_value = _mapping("text")
    client.count.return_value = {"count": 4}

    result = plan_or_apply_case_id_backfill(client, "case-foo", apply=True)

    assert result["status"] == "requires_reindex"
    assert result["incompatible_indices"] == ["case-foo-evtx-host"]
    client.indices.put_mapping.assert_not_called()
    client.update_by_query.assert_not_called()


def test_keyword_mapping_with_partial_term_coverage_fails_measurement():
    client = MagicMock()
    client.indices.get_mapping.return_value = _mapping("keyword")
    client.count.side_effect = [{"count": 4}, {"count": 3}]
    client.update_by_query.return_value = {"updated": 4}

    result = plan_or_apply_case_id_backfill(client, "case-foo", apply=True)

    assert result["status"] == "count_mismatch"
    assert result["mismatched_indices"] == ["case-foo-evtx-host"]
