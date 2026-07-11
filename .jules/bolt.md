## 2026-07-11 - Optimize Date parsing in hot loops
**Learning:** Instantiating `new Date()` inside hot loops (like sorting and filtering) creates significant performance overhead. Using plain `Date.parse()` can break on variable precision or mixed types.
**Action:** Use a robust helper `t?.getTime ? t.getTime() : typeof t === 'number' ? t : (Date.parse(t) || 0)` to avoid object allocation and ensure accurate time comparisons.
