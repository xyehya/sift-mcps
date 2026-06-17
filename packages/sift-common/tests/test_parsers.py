"""Tests for sift_common.parsers — csv, json, and text output parsers."""

from __future__ import annotations

from sift_common.parsers.csv_parser import parse_csv, parse_csv_file
from sift_common.parsers.json_parser import parse_json, parse_jsonl
from sift_common.parsers.text_parser import extract_lines, parse_text

# ---------------------------------------------------------------------------
# CSV parser
# ---------------------------------------------------------------------------


class TestParseCsv:
    def test_empty_input(self):
        result = parse_csv("")
        assert result["rows"] == []
        assert result["total_rows"] == 0
        assert result["truncated"] is False
        assert result["columns"] == []

    def test_whitespace_only(self):
        result = parse_csv("   \n  ")
        assert result["rows"] == []

    def test_basic_csv(self):
        text = "name,age\nAlice,30\nBob,25"
        result = parse_csv(text)
        assert result["total_rows"] == 2
        assert result["truncated"] is False
        assert result["columns"] == ["name", "age"]
        assert result["rows"][0] == {"name": "Alice", "age": "30"}
        assert result["rows"][1] == {"name": "Bob", "age": "25"}

    def test_max_rows_truncation(self):
        # header + 6 data rows; the for-loop consumes one row past max_rows
        # before breaking, so total_rows = 3 returned + 2 remaining = 5
        text = "id\n1\n2\n3\n4\n5\n6"
        result = parse_csv(text, max_rows=3)
        assert len(result["rows"]) == 3
        assert result["total_rows"] == 5
        assert result["truncated"] is True

    def test_byte_budget_truncation(self):
        text = "name\naaaa\nbbbb\ncccc"
        result = parse_csv(text, byte_budget=10)
        assert len(result["rows"]) >= 1
        assert result["preview_bytes"] > 0

    def test_byte_budget_allows_first_row_even_if_over(self):
        text = "name\naaaaaaaaaa"
        result = parse_csv(text, byte_budget=1)
        assert len(result["rows"]) == 1

    def test_header_only(self):
        text = "col1,col2"
        result = parse_csv(text)
        assert result["rows"] == []
        assert result["total_rows"] == 0
        assert result["columns"] == ["col1", "col2"]

    def test_preview_rows_and_bytes_fields(self):
        text = "x\n1\n2\n3"
        result = parse_csv(text)
        assert result["preview_rows"] == 3


class TestParseCsvFile:
    def test_file_not_found(self):
        result = parse_csv_file("/nonexistent/file.csv")
        assert result["rows"] == []
        assert "parse_error" in result

    def test_reads_valid_file(self, tmp_path):
        f = tmp_path / "data.csv"
        f.write_text("a,b\n1,2\n3,4")
        result = parse_csv_file(str(f))
        assert result["total_rows"] == 2
        assert result["rows"][0] == {"a": "1", "b": "2"}

    def test_rejects_oversized_file(self, tmp_path):
        f = tmp_path / "big.csv"
        f.write_bytes(b"x" * (50_000_001))
        result = parse_csv_file(str(f))
        assert "error" in result


# ---------------------------------------------------------------------------
# JSON parser
# ---------------------------------------------------------------------------


class TestParseJson:
    def test_empty_input(self):
        result = parse_json("")
        assert result["data"] is None
        assert result["total_entries"] == 0
        assert result["truncated"] is False

    def test_whitespace_only(self):
        result = parse_json("   ")
        assert result["data"] is None

    def test_invalid_json(self):
        result = parse_json("{bad json}")
        assert result["data"] is None
        assert "parse_error" in result

    def test_single_object(self):
        result = parse_json('{"key": "value"}')
        assert result["data"] == {"key": "value"}
        assert result["total_entries"] == 1
        assert result["truncated"] is False

    def test_array(self):
        result = parse_json('[1, 2, 3]')
        assert result["data"] == [1, 2, 3]
        assert result["total_entries"] == 3
        assert result["truncated"] is False

    def test_array_max_entries(self):
        import json

        arr = list(range(10))
        result = parse_json(json.dumps(arr), max_entries=5)
        assert len(result["data"]) == 5
        assert result["total_entries"] == 10
        assert result["truncated"] is True

    def test_array_byte_budget(self):
        import json

        arr = [{"v": "x" * 100} for _ in range(10)]
        result = parse_json(json.dumps(arr), byte_budget=200)
        assert len(result["data"]) >= 1
        assert result["preview_bytes"] > 0

    def test_array_byte_budget_allows_first_entry(self):
        import json

        arr = [{"v": "x" * 1000}]
        result = parse_json(json.dumps(arr), byte_budget=1)
        assert len(result["data"]) == 1


class TestParseJsonl:
    def test_empty_input(self):
        result = parse_jsonl("")
        assert result["data"] == []
        assert result["total_entries"] == 0

    def test_basic_jsonl(self):
        text = '{"a": 1}\n{"a": 2}\n{"a": 3}'
        result = parse_jsonl(text)
        assert len(result["data"]) == 3
        assert result["total_entries"] == 3
        assert result["truncated"] is False

    def test_skips_blank_lines(self):
        text = '{"a": 1}\n\n{"a": 2}\n'
        result = parse_jsonl(text)
        assert len(result["data"]) == 2
        assert result["total_entries"] == 2

    def test_invalid_line_becomes_raw(self):
        text = '{"ok": true}\nnot json\n{"ok": false}'
        result = parse_jsonl(text)
        assert len(result["data"]) == 3
        assert result["data"][1] == {"_raw": "not json"}

    def test_max_entries(self):
        text = "\n".join(f'{{"i": {i}}}' for i in range(10))
        result = parse_jsonl(text, max_entries=3)
        assert len(result["data"]) == 3
        assert result["total_entries"] == 10
        assert result["truncated"] is True

    def test_byte_budget(self):
        text = "\n".join(f'{{"i": {i}}}' for i in range(10))
        result = parse_jsonl(text, byte_budget=20)
        assert len(result["data"]) >= 1
        assert result["preview_bytes"] > 0


# ---------------------------------------------------------------------------
# Text parser
# ---------------------------------------------------------------------------


class TestParseText:
    def test_empty_input(self):
        result = parse_text("")
        assert result["lines"] == [""]
        assert result["total_lines"] == 1
        assert result["truncated"] is False

    def test_basic_lines(self):
        result = parse_text("line1\nline2\nline3")
        assert result["lines"] == ["line1", "line2", "line3"]
        assert result["total_lines"] == 3
        assert result["truncated"] is False

    def test_max_lines_truncation(self):
        text = "\n".join(f"line{i}" for i in range(10))
        result = parse_text(text, max_lines=5)
        assert len(result["lines"]) == 5
        assert result["total_lines"] == 10
        assert result["truncated"] is True
        assert result["preview_lines"] == 5

    def test_byte_budget(self):
        text = "\n".join("x" * 50 for _ in range(10))
        result = parse_text(text, byte_budget=100)
        assert len(result["lines"]) >= 1
        assert result["preview_bytes"] > 0

    def test_byte_budget_allows_first_line(self):
        text = "x" * 1000
        result = parse_text(text, byte_budget=1)
        assert len(result["lines"]) == 1


class TestExtractLines:
    def test_basic_extraction(self):
        text = "a\nb\nc\nd\ne"
        assert extract_lines(text, start=1, count=2) == ["b", "c"]

    def test_start_at_zero(self):
        text = "a\nb\nc"
        assert extract_lines(text, start=0, count=2) == ["a", "b"]

    def test_beyond_end(self):
        text = "a\nb"
        result = extract_lines(text, start=0, count=100)
        assert result == ["a", "b"]
