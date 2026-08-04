import { extractDate, extractTime } from './packages/case-dashboard/frontend/src/lib/timestamp-utils.js';

console.log(extractDate('2026-01-02T03:04:05.000Z')); // 2026-01-02
console.log(extractTime('2026-01-02T03:04:05.000Z')); // 03:04:05
console.log(extractDate(1767236645000));
console.log(extractTime(1767236645000));
