"""Canonical identifier/slug contracts shared across the SIFT platform.

Single source of truth for the examiner/principal slug pattern. Before this
module the pattern ``^[a-z0-9][a-z0-9-]{0,19}$`` was copy-pasted into
``sift_common.audit``, ``sift_core.{case_io,approval_auth,identity,case_manager}``
and ``case_dashboard.routes`` — six independent literals that could drift apart.

The examiner slug gates principal identities that flow into filesystem paths
(``passwords/{examiner}.json``, case/audit directories), audit JSONL lines, and
DB rows. It is therefore a strict positive allow-list, validated as a *complete*
string (see the ``\\Z`` note below), per the input-validation guidance.
"""

from __future__ import annotations

import re

# Strict allow-list for examiner / principal slugs:
#   * first character: a single lowercase letter or digit
#   * then 0..19 of [a-z0-9-]  ->  total length 1..20
#   * ``\Z`` (not ``$``) anchors the *end of string*. ``$`` additionally matches
#     just before a trailing newline, so the old ``$`` form accepted values like
#     ``"alice\n"``; ``\Z`` rejects any trailing content, including newlines, which
#     is the safe behavior for a slug used in paths and single-line audit records.
# The pattern is linear-time (no backtracking ambiguity) -> not ReDoS-prone.
EXAMINER_SLUG_PATTERN = r"^[a-z0-9][a-z0-9-]{0,19}\Z"
EXAMINER_SLUG_RE = re.compile(EXAMINER_SLUG_PATTERN)

# Maximum slug length, kept in sync with the pattern's ``{0,19}`` bound (1 + 19).
EXAMINER_SLUG_MAX_LEN = 20


def is_valid_examiner_slug(value: str) -> bool:
    """Return ``True`` iff *value* is a valid examiner/principal slug.

    Equivalent to ``bool(EXAMINER_SLUG_RE.match(value))``. Empty strings, any
    value containing path separators, dots, whitespace, uppercase letters, NUL,
    trailing newlines, or other metacharacters are rejected. Callers own their
    own error/``None`` semantics on rejection.
    """
    return EXAMINER_SLUG_RE.match(value) is not None
