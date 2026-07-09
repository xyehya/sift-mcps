
## 2024-05-23 - Optimizing Date Parsing in Hot Loops
**Learning:** Instantiating `new Date()` within array `.filter()` and `.sort()` callbacks across large datasets causes significant performance overhead in the rendering and derived state loops. Standard string sorting isn't always safe if timestamps vary in format.
**Action:** Use a robust parsing utility `parseMs(t) { return t?.getTime ? t.getTime() : typeof t === 'number' ? t : (Date.parse(t) || 0) }` instead of `new Date(ts).getTime()` in mapping, filtering, and sorting loops.
