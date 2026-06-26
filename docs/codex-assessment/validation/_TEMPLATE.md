# Validation — Cluster {CLUSTER_NAME}

> Validator agent: {AGENT_NAME} (Opus 4.8, xhigh). Read-only. Validates the restored
> Codex assessment against **current HEAD**, not the stale scan base `b995491` (≈183
> commits old; the line numbers in `codex_review_directives.txt` are stale and MUST be
> re-located). No source code was modified — this file is the only output.

## Summary table

| Candidate | Codex verdict | **Current status** | Current severity | Confidence | Already-fixed-by | Fix effort |
|---|---|---|---|---|---|---|
| DSS-CAN-0XX | valid/partial | STILL-VALID / PARTIALLY-FIXED / ALREADY-FIXED / FALSE-POSITIVE / NEEDS-OPERATOR-DECISION | High/Med/Low | high/med/low | commit/migration or "—" | S/M/L |

---

## DSS-CAN-0XX — <title>

**Codex claim (verbatim intent):** …

**Current code located at:** `path/to/file.py:NEW_START-NEW_END` (codex cited `OLD_START-OLD_END` on `b995491`)

**Drift since scan:** `git log --oneline b995491..HEAD -- <file>` → (summarize; did any commit touch this?)

**CURRENT STATUS:** STILL-VALID | PARTIALLY-FIXED | ALREADY-FIXED | FALSE-POSITIVE | NEEDS-OPERATOR-DECISION

**Evidence (current source):**
```python
# exact current snippet proving the status, with file:line
```
Trace / data-flow that proves reachability (callers, the entry surface, which middleware does/doesn't run):
- …

**Exploit preconditions (who can trigger, what auth/role/scope/case-state is required):** …

**Blast radius if valid:** …

**Project-invariant check:** does the claim/fix interact with — DB-authority (agent backend has no DB creds), gateway-as-policy-boundary, the MCP surfacing layers (registry `*Out` + worker `result_public` + DB-authority path), the evidence gate, least-priv sandbox, portal-managed lifecycle? Note any interaction.

**FIX APPROACH (secure-by-design, preserves invariants, NOT monkey-patching):**
- Root cause: …
- Proposed change (where it must land — name the exact function/layer; if it needs the surfacing layers, say so): …
- Why it preserves project identity/invariants: …
- Test strategy (unit + surface/conformance test that fails-on-revert; live deploy-and-prove step if behavior, not just plumbing): …
- Alternatives considered / rejected and why: …

**Cross-cluster dependency:** (e.g. "shares a fix with DSS-CAN-0YY in cluster BACKENDS — both need one shared egress policy") or "none".

**Open question for operator (if any):** …
