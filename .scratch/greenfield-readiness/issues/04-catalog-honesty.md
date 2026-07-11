# 04 — Make the tool catalog operationally honest

**What to build:** ensure catalog and help information accurately communicate Windows-only tooling, synchronous versus durable-job execution, and the actual yara inventory.

**Blocked by:** 01 — Reconcile the current-main CI baseline.

**Status:** completed — integrated with discovery-path review remediation as `06d589d`; final combined-batch review remains.

- [ ] Remove claims that advertise an unusable platform or execution path.
- [ ] Add regression tests that fail if the corrected availability truth reverts.
- [ ] Validate affected API/UI surfaces and the rebuilt bundle where applicable.
- [ ] Apply CodeGuard web/API/MCP guidance and report the verdict.
