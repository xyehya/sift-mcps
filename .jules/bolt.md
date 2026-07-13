## 2024-07-13 - Date parsing overhead in Timeline components
**Learning:** Instantiating `new Date(ISOString)` just to extract date and time substrings or calculate timestamps creates unnecessary allocation overhead in hot rendering loops, such as when processing many `TimelineEvent` components.
**Action:** Use fast-path string slicing for ISO 8601 strings to extract substrings (like `substring(0,10)` for dates and `substring(11,19)` for time) and fall back to `parseTimestamp()` or Date allocations only when necessary.
