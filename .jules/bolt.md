## 2023-11-20 - [Timeline Sorting Optimization]
**Learning:** `new Date(string)` inside Array.sort() is a significant bottleneck on large arrays due to redundant string-to-date parsing (O(N log N) overhead).
**Action:** Use the map-sort-map pattern (Schwartzian transform) to parse dates exactly once per item (O(N)) before sorting. This yields a massive (~10x+) speedup for date-heavy tabular data and timelines.
