## 2024-10-24 - Fast-Path Timestamp Extraction
**Learning:** Instantiating `new Date(string)` inside hot loops like React map renders (e.g. `TimelineTab` mapping hundreds of events) incurs a massive performance penalty. Using string slicing for valid ISO strings is significantly faster but must rigorously verify timezone (e.g., ends in 'Z') to avoid UTC vs local bugs.
**Action:** Use the `extractDate` and `extractTime` utilities in `@/components/common/entity-utils` instead of formatting `new Date` to display dates/times from raw data strings in React component loops.
