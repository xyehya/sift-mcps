## 2025-01-18 - Fast-Path Timestamp Slicing
**Learning:** `new Date(iso).toISOString()` causes heavy allocation overhead in hot paths (like timeline rendering) when the input is already a valid ISO string.
**Action:** Use fast-path string slicing via `extractDate` and `extractTime` in `@/components/common/entity-utils` to avoid allocating `Date` objects for standard ISO timestamp properties.
