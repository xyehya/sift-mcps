"""Tests for the canonical examiner/principal slug contract (XYE-69 / D1).

These prove the single-source validator in ``sift_common.identifiers`` accepts
and rejects exactly the same inputs the six previously-duplicated copies did —
with one deliberate, documented hardening: the canonical pattern anchors on
``\\Z`` instead of ``$``, so a value with a trailing newline is now rejected.
"""

from __future__ import annotations

import re

import pytest
from sift_common.identifiers import (
    EXAMINER_SLUG_MAX_LEN,
    EXAMINER_SLUG_PATTERN,
    is_valid_examiner_slug,
)

# The exact literal that was copy-pasted across sift-common / sift-core /
# case-dashboard before D1. Used here to prove equivalence on all non-newline
# inputs (the only intended divergence is trailing-newline handling).
_LEGACY_PATTERN = r"^[a-z0-9][a-z0-9-]{0,19}$"
_LEGACY_RE = re.compile(_LEGACY_PATTERN)

VALID = [
    "a",
    "0",
    "alice",
    "bob-smith",
    "analyst1",
    "a-0-b",
    "z" * EXAMINER_SLUG_MAX_LEN,          # exactly 20 chars
    "0" + "a" * (EXAMINER_SLUG_MAX_LEN - 1),
]

INVALID = [
    "",                       # empty
    "-alice",                 # leading hyphen
    "A",                      # uppercase
    "Alice",
    "ALICE",
    "alice.bob",              # dot
    "alice bob",              # space
    "alice@x",                # at-sign
    "alice/bob",              # path separator
    "alice\\bob",             # backslash
    "../etc/passwd",          # path traversal
    "a" * (EXAMINER_SLUG_MAX_LEN + 1),    # 21 chars, too long
    "café",                   # non-ascii
    "ali\x00ce",              # embedded NUL
    "\x00",                   # NUL only
    "alice\nbob",             # embedded newline
]


@pytest.mark.parametrize("value", VALID)
def test_accepts_valid_slugs(value: str) -> None:
    assert is_valid_examiner_slug(value) is True


@pytest.mark.parametrize("value", INVALID)
def test_rejects_invalid_slugs(value: str) -> None:
    assert is_valid_examiner_slug(value) is False


@pytest.mark.parametrize("value", VALID + INVALID)
def test_equivalent_to_legacy_pattern_on_non_newline_inputs(value: str) -> None:
    """The canonical contract must match the old literal for every input that
    does not rely on the ``$`` trailing-newline quirk."""
    assert is_valid_examiner_slug(value) == bool(_LEGACY_RE.match(value))


def test_trailing_newline_is_the_one_intended_divergence() -> None:
    """Document the single behavior change vs the legacy ``$`` pattern.

    ``$`` matched just before a trailing newline, so the old validators accepted
    ``"alice\\n"``. The canonical ``\\Z`` contract rejects it, which is the safe
    behavior for a slug used in filesystem paths and single-line audit records.
    """
    assert _LEGACY_RE.match("alice\n") is not None      # legacy: accepted (quirk)
    assert is_valid_examiner_slug("alice\n") is False    # canonical: rejected


def test_pattern_is_complete_string_anchored() -> None:
    assert EXAMINER_SLUG_PATTERN.endswith(r"\Z")
    # No partial / prefix match: a valid prefix followed by junk is rejected.
    assert is_valid_examiner_slug("alice#") is False
