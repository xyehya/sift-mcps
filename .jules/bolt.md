## 2025-02-24 - Fast-path Timestamp Extraction
**Learning:** Instantiating `new Date(ts).toISOString()` in hot loops (like rendering Timeline events) creates massive allocation overhead and garbage collection pauses. Naive string slicing of timestamps can introduce timezone offset bugs if the string isn't explicitly UTC ('Z').
**Action:** Use fast-path string slicing with a `.endsWith('Z')` check to extract date/time parts safely without Date allocations, falling back to `new Date()` only when necessary. Prefer utility functions `extractDate` and `extractTime` from `entity-utils`.
