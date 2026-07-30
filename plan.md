1. **Add `extractDate` and `extractTime` to `timestamp-utils.js`**
   - Implement fast-path UTC date/time extraction functions avoiding `new Date()` allocations for valid ISO strings ending in 'Z'.
   - This prevents timezone offset bugs and garbage collection overhead in hot loops.
2. **Export new functions from `entity-utils.js`**
   - Modify `packages/case-dashboard/frontend/src/components/common/entity-utils.js` to re-export `extractDate` and `extractTime`.
3. **Refactor `TimelineEvent.jsx` to use optimized timestamp functions**
   - Replace `new Date(ts).getTime()` with `parseTimestamp(ts)`.
   - Replace `new Date(ts).toISOString().substring(...)` with `extractDate` and `extractTime`.
4. **Refactor `TimelineTab.jsx` to use optimized timestamp functions**
   - Replace `new Date(ts).toDateString()` with `extractDate(ts)` for checking date changes.
5. **Add tests for `extractDate` and `extractTime`**
   - In `timestampUtils.test.js`, add test cases for fast paths and fallback behaviors.
6. **Pre-Commit Steps**
   - Complete pre-commit steps to ensure proper testing, verification, review, and reflection are done.
7. **Submit Pull Request**
   - PR Title: `⚡ Bolt: [performance improvement]`
   - Add required details (What, Why, Impact, Measurement) and commit the changes.
