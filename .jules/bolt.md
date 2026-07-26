
## 2024-07-26 - Fast-Path Timestamp Extraction
**Learning:** In hot loops like the timeline render mapping, allocating `new Date()` just to extract the date (e.g. for separation logic `new Date(ts).toDateString()`) or time string causes significant overhead and can lead to bugs due to local vs UTC timezone mismatch (`.toDateString()` uses local time whereas the timestamps are UTC).
**Action:** Use fast-path string slicing to extract the date (YYYY-MM-DD) or time (HH:MM:SS) directly from standard UTC ISO strings without allocating new Date objects. Implemented `extractDate` and `extractTime` utilities in `@/lib/timestamp-utils` that perform this safely by validating the ISO string format first.
