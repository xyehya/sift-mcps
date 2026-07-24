## 2024-07-24 - Timestamp parsing in hot loops
**Learning:** Instantiating `new Date()` within hot render loops (like timeline lists with hundreds of events) causes unnecessary object allocation and garbage collection overhead, particularly for simple string formatting. Relying on `.toDateString()` and `.toISOString()` together causes UTC vs Local timezone mismatches.
**Action:** Use fast-path string slicing for valid ISO strings (verifying they end in 'Z' to avoid UTC offset issues) to extract date and time parts directly, skipping `new Date()` allocation entirely.
