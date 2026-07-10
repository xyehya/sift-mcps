## 2024-07-10 - Date parsing in hot loops
**Learning:** `new Date()` instantiation overhead in filter/sort loops is a significant bottleneck. Using `Date.parse()` or falling back to raw number/already instantiated Date objects is much more efficient.
**Action:** Use a robust `parseTimestamp` helper instead of `new Date()` inside loops across frontend lists and tables.
