"""AUT2-B1: bounded printable-strings extraction from forensic images.

Covers the streaming extractor itself: ASCII + UTF-16LE detection with
correct offsets, chunk-boundary spanning, min-length filtering, and both
truncation bounds (max_strings cap and the byte budget).
"""

from __future__ import annotations

import io

from opensearch_mcp.image_strings import StringScanStats, iter_image_strings

_NOISE = bytes(range(0, 32)) * 4  # 128 bytes, no printable runs


def _scan(data: bytes, **kwargs):
    stats = kwargs.pop("stats", None) or StringScanStats()
    found = list(iter_image_strings(io.BytesIO(data), stats=stats, **kwargs))
    return found, stats


def test_extracts_ascii_and_utf16_strings_with_offsets():
    ascii_payload = b"malicious-c2.example.net"
    utf16_payload = "powershell -enc SQBFAFgA".encode("utf-16-le")
    data = _NOISE + ascii_payload + _NOISE + utf16_payload + _NOISE

    found, stats = _scan(data)

    assert (len(_NOISE), "ascii", "malicious-c2.example.net") in found
    utf16_offset = len(_NOISE) + len(ascii_payload) + len(_NOISE)
    assert (utf16_offset, "utf-16le", "powershell -enc SQBFAFgA") in found
    assert len(found) == 2
    assert stats.bytes_scanned == len(data)
    assert stats.strings_emitted == 2
    assert stats.truncated is False


def test_short_runs_below_min_length_are_ignored():
    data = _NOISE + b"tiny" + _NOISE + b"exactly" + _NOISE
    found, _stats = _scan(data, min_length=6)
    assert [text for _off, _enc, text in found] == ["exactly"]


def test_string_spanning_chunk_boundary_is_kept_whole():
    payload = b"boundary-spanning-string-payload"
    data = b"\x01" * 10 + payload + b"\x02" * 10
    found, stats = _scan(data, chunk_size=16)
    assert found == [(10, "ascii", payload.decode("ascii"))]
    assert stats.bytes_scanned == len(data)


def test_max_strings_cap_sets_truncated():
    parts = [b"string-number-%03d" % i for i in range(20)]
    data = b"\xff\xfe".join(parts)
    found, stats = _scan(data, max_strings=5)
    assert len(found) == 5
    assert stats.truncated is True


def test_byte_budget_sets_truncated_and_stops_reading():
    data = _NOISE + b"early-visible-string" + _NOISE + b"\x03" * 4096 + b"late-string"
    budget = len(_NOISE) + 20 + len(_NOISE)
    found, stats = _scan(data, max_scan_bytes=budget, chunk_size=64)
    assert [text for _off, _enc, text in found] == ["early-visible-string"]
    assert stats.bytes_scanned == budget
    assert stats.truncated is True


def test_budget_equal_to_file_size_is_not_truncated():
    data = _NOISE + b"only-string-here"
    found, stats = _scan(data, max_scan_bytes=len(data))
    assert [text for _off, _enc, text in found] == ["only-string-here"]
    assert stats.truncated is False
