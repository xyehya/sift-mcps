## 2024-07-15 - Fast-path timestamp allocation
**Learning:** Instantiating `new Date(ts).toISOString()` in hot loops (e.g. mapping over timelines or event lists) causes unnecessary memory allocation overhead.
**Action:** Use fast-path string slicing (like `substring(0, 10)` for date, `substring(11, 19)` for time) when extracting date or time parts if the timestamp is already a valid ISO string. Fallback to `new Date` allocation only if necessary.
