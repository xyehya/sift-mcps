"""F7: opensearch_search sort body must not attach `unmapped_type` to meta-fields.

Root cause (server.py): the sort body unconditionally added
`unmapped_type: "date"` to every sort field, including the OpenSearch meta-fields
`_score` and `_doc`.  `unmapped_type` is invalid for meta-fields, so OpenSearch
returns a 400 and the tool surfaced an opaque "tool execution failed".

Fix: `_build_sort_body` omits `unmapped_type` for meta-fields and keeps it for
real document fields (mixed-mapping guard).  A backend sort rejection still maps
to a typed ValueError("Query error: ...") via _os_call's RequestError handler.
"""

from __future__ import annotations

from opensearch_mcp.server import _SORT_META_FIELDS, _build_sort_body


class TestBuildSortBody:
    def test_score_desc_has_no_unmapped_type(self):
        body = _build_sort_body("_score:desc")
        assert body == [{"_score": {"order": "desc"}}]
        assert "unmapped_type" not in body[0]["_score"]

    def test_score_default_order_no_unmapped_type(self):
        # "_score" with no explicit order → defaults to desc, still no unmapped_type.
        body = _build_sort_body("_score")
        assert body == [{"_score": {"order": "desc"}}]

    def test_doc_meta_field_no_unmapped_type(self):
        body = _build_sort_body("_doc:asc")
        assert body == [{"_doc": {"order": "asc"}}]
        assert "unmapped_type" not in body[0]["_doc"]

    def test_real_field_keeps_unmapped_type(self):
        body = _build_sort_body("@timestamp:desc")
        assert body == [{"@timestamp": {"order": "desc", "unmapped_type": "date"}}]

    def test_arbitrary_real_field_keeps_unmapped_type(self):
        body = _build_sort_body("EventID:asc")
        assert body[0]["EventID"]["order"] == "asc"
        assert body[0]["EventID"]["unmapped_type"] == "date"

    def test_empty_sort_defaults_to_timestamp_desc(self):
        body = _build_sort_body("")
        assert body == [{"@timestamp": {"order": "desc", "unmapped_type": "date"}}]

    def test_blank_sort_defaults_to_timestamp_desc(self):
        assert _build_sort_body("   ") == [
            {"@timestamp": {"order": "desc", "unmapped_type": "date"}}
        ]

    def test_invalid_order_falls_back_to_desc(self):
        body = _build_sort_body("EventID:sideways")
        assert body[0]["EventID"]["order"] == "desc"

    def test_field_only_no_order_defaults_desc(self):
        body = _build_sort_body("EventID")
        assert body[0]["EventID"]["order"] == "desc"
        assert body[0]["EventID"]["unmapped_type"] == "date"

    def test_meta_fields_constant_contains_score_and_doc(self):
        assert "_score" in _SORT_META_FIELDS
        assert "_doc" in _SORT_META_FIELDS
