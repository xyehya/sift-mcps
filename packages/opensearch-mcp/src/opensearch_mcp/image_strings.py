"""Bounded printable-strings extraction from forensic image files (AUT2-B1).

Streams a disk image (raw/dd/img, or E01 via optional pyewf) in fixed-size
chunks and yields printable ASCII and UTF-16LE strings with their byte
offsets — no mounting, no full-file buffering. Extraction is bounded by both
a byte budget and a max-strings cap so a multi-hundred-GB image can never
stall the job worker; hitting either bound sets ``truncated`` on the scan
stats so the caller can surface it in the job result.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Iterator

DEFAULT_MIN_LENGTH = 6
DEFAULT_MAX_STRINGS = 500_000
DEFAULT_MAX_SCAN_BYTES = 2 * 1024**3  # 2 GiB
DEFAULT_CHUNK_SIZE = 4 * 1024**2  # 4 MiB

# Longest carry kept across chunk boundaries. A printable run longer than
# this is emitted in pieces (acceptable for forensic strings triage).
_MAX_CARRY = 64 * 1024

# Bytes that can belong to either pattern (printable ASCII or the NULs of
# UTF-16LE). The trailing run of these is carried into the next chunk so a
# string spanning a boundary is not lost.
_STRING_BYTES = frozenset(range(0x20, 0x7F)) | {0x00}


def _tail_run_start(data: bytes) -> int:
    """Start index of the trailing maybe-string run, capped at ``_MAX_CARRY``."""
    start = len(data)
    limit = max(0, len(data) - _MAX_CARRY)
    while start > limit and data[start - 1] in _STRING_BYTES:
        start -= 1
    return start


@dataclass
class StringScanStats:
    """Mutable counters for one image scan (shared with the caller)."""

    bytes_scanned: int = 0
    strings_emitted: int = 0
    truncated: bool = False


def iter_image_strings(
    stream: Any,
    *,
    min_length: int = DEFAULT_MIN_LENGTH,
    max_strings: int = DEFAULT_MAX_STRINGS,
    max_scan_bytes: int = DEFAULT_MAX_SCAN_BYTES,
    chunk_size: int = DEFAULT_CHUNK_SIZE,
    stats: StringScanStats | None = None,
) -> Iterator[tuple[int, str, str]]:
    """Yield ``(offset, encoding, text)`` for each printable string found.

    ``stream`` only needs a ``read(size) -> bytes`` method (regular file
    object or a pyewf handle). ``encoding`` is ``"ascii"`` or ``"utf-16le"``.
    Offsets are absolute byte offsets of the string start within the stream.
    """
    if stats is None:
        stats = StringScanStats()
    min_length = max(1, int(min_length))
    ascii_re = re.compile(rb"[\x20-\x7e]{%d,}" % min_length)
    utf16_re = re.compile(rb"(?:[\x20-\x7e]\x00){%d,}" % min_length)

    carry = b""
    carry_offset = 0
    next_offset = 0
    while True:
        budget = max_scan_bytes - stats.bytes_scanned
        if budget <= 0:
            # Budget exhausted — truncated only if there is more data.
            if stream.read(1):
                stats.truncated = True
            break
        chunk = stream.read(min(chunk_size, budget))
        if not chunk:
            break
        stats.bytes_scanned += len(chunk)
        data = carry + chunk
        base = next_offset - len(carry)
        next_offset += len(chunk)

        # Keep the trailing maybe-string run (capped) for the next chunk.
        tail_start = _tail_run_start(data)
        region, carry = data[:tail_start], data[tail_start:]
        carry_offset = base + tail_start

        yield from _emit_region(region, base, ascii_re, utf16_re, max_strings, stats)
        if stats.truncated:
            return

    if carry and not stats.truncated:
        yield from _emit_region(carry, carry_offset, ascii_re, utf16_re, max_strings, stats)


def _emit_region(
    region: bytes,
    base: int,
    ascii_re: re.Pattern,
    utf16_re: re.Pattern,
    max_strings: int,
    stats: StringScanStats,
) -> Iterator[tuple[int, str, str]]:
    """Yield all matches in one fully-buffered region, ordered by offset."""
    matches: list[tuple[int, str, str]] = []
    for match in ascii_re.finditer(region):
        matches.append((base + match.start(), "ascii", match.group().decode("ascii")))
    for match in utf16_re.finditer(region):
        matches.append(
            (base + match.start(), "utf-16le", match.group().decode("utf-16-le"))
        )
    matches.sort(key=lambda item: item[0])
    for item in matches:
        if stats.strings_emitted >= max_strings:
            stats.truncated = True
            return
        stats.strings_emitted += 1
        yield item
