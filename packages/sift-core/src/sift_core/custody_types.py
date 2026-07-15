"""Shared custody value types, independent of evidence-file storage."""

from enum import Enum


class ChainStatus(str, Enum):  # noqa: UP042
    OK = "ok"
    UNSEALED = "unsealed"
    MODIFIED = "modified"
    MISSING = "missing"
    UNREGISTERED = "unregistered"
    LEDGER_ERROR = "ledger_error"
