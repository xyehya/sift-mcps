"""Local-immutable evidence storage profile.

External / by-reference (mounted, removable, network-backed) evidence storage was
removed in the P4.23 CP3 custody sweep. The only supported storage profile is
local immutable evidence — its guarantees come from service ownership, a fixed
mode, and the immutable flag, revalidated per read against a pinned descriptor.
Supporting any other storage would require a new product decision and
architecture; it is not a dormant profile here.

Authority: ``docs/architecture/EVIDENCE-CUSTODY-SPEC.md`` (Local storage only).
"""

from __future__ import annotations

from enum import StrEnum


class StorageProfile(StrEnum):
    """The single supported evidence storage profile."""

    LOCAL_IMMUTABLE = "LOCAL_IMMUTABLE"
