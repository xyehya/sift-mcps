
## 2024-07-04 - ISO-8601 Timestamp Sorting Optimization
**Learning:** For performance, parsing ISO-8601 strings into dates using `new Date()` incurs unnecessary instantiation overhead in hot loops like `Array.sort()`.
**Action:** Prefer lexicographical string comparisons over parsing with `new Date()` when sorting ISO 8601 timestamp strings, as their lexical order exactly matches chronological order. This avoids date creation overhead entirely.
