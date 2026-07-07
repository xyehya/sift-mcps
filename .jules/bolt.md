## 2024-05-18 - Avoid `new Date()` in sorting hot loops
**Learning:** Instantiating `new Date()` inside Array.sort() callbacks for ISO 8601 strings creates a measurable CPU and memory bottleneck, as date parsing happens for every comparison.
**Action:** Always prefer lexicographical string comparisons (`<` and `>`) when sorting ISO 8601 formatted strings instead of parsing to Dates.
