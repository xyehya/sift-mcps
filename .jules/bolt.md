## 2024-07-16 - Optimize hot loops Date allocation
**Learning:** `new Date()` allocation inside list rendering hot loops (like in TimelineEvent formatting or timeline grouping checks) introduces measurable memory allocation overhead, and using `.toDateString()` risks local vs UTC timezone mismatch bugs.
**Action:** Use fast-path string slicing logic (e.g. `extractDate`, `extractTime`) when input dates are already valid ISO strings to avoid unnecessary `new Date()` instantiations and local timezone bugs.
