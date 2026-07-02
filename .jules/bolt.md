## 2024-05-24 - [Vite App Context]
**Learning:** React Vite application requires a specific version of Node/npm as stated in warning. Will use standard optimizations.
**Action:** Always check the warning logs and stick to React performance optimizations without updating packages unless needed.

## 2026-07-02 - [JS Sort Bottleneck]
**Learning:** Instantiating `new Date` inside `Array.prototype.sort()` callbacks is extremely slow in JS because sort executes O(N log N) times.
**Action:** Always prefer lexicographical string comparisons for ISO 8601 strings when sorting natively, as it yields an approximate ~10x speedup.
