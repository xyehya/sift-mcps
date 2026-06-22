# RUN — Portal v3 · P3.5 parallel drive (agent via MCP tools ↔ operator via portal)

Next-session handoff. The portal is deployed + browser-verified on the live SIFT VM with a
hardened CSP; the case is real but **empty** (0 findings). This session **populates it with real
data via the gateway MCP tools** while the operator watches the portal — validating the end-to-end
loop **MCP action → gateway → DB → portal UI** in parallel.

Prereq: a fresh agent JWT (`mcp:*`, bound to the active ROCBA case) is in `~/.claude/settings.json`
(+ `NODE_EXTRA_CA_CERTS` → VM CA). Relaunching `claude` loads it, so the `mcp__Siftmcp__*` tools
should be present. If they are NOT, the token didn't load — relaunch `claude -c` from a shell that
reads `settings.json`.

---

## READY-TO-PASTE kickoff prompt

```
Kickoff — SIFT Examiner Portal v3, P3.5 parallel drive: I (agent) run the DFIR workflow via the
in-session Siftmcp MCP tools; you (operator) monitor the portal and test the examiner side in
parallel. Goal = validate the end-to-end loop MCP action → gateway → DB → portal UI on real data,
and populate the currently-empty ROCBA case.

Context: Portal v3 is deployed + browser-verified on the live SIFT VM (https://192.168.122.81:4508,
/opt/sift-mcps, aligned to main+portal, hardened CSP live). A fresh agent JWT (mcp:*, bound to the
active ROCBA case) is in ~/.claude/settings.json, so the mcp__Siftmcp__* gateway tools should be
LOADED. Active case = "ROCBA EXFILTRAT" (id beda8702-…; evidence dir case-rocba-3-06171852). The
portal reads /api/{findings,timeline,iocs,todos,evidence,...} from the SAME DB the MCP tools write,
so my actions should surface live in your portal.

Recall memory: [[reference_harness_mcp_live_connection]], [[vm_sift_coordinates]],
[[project_portal_v3_rebuild]], [[project_lv1_live_test]], [[project_run_command_security]],
[[project_rocba_case]].

Start (do in order, narrate each step so I can follow in the portal):
1. Confirm the surface: list the mcp__Siftmcp__* tools. If NONE are present, STOP and tell me to
   relaunch `claude -c` (the token didn't load). Do not proceed without them.
2. Verify case context: call case_info (+ list_existing_findings, chain_status). Confirm the active
   case is ROCBA and evidence is sealed. If you hit `active_case_membership_required`, surface it —
   the token was issued while ROCBA was active so it should be a member.
3. Inventory which tools WRITE portal-visible data (record findings, timeline entries, IOCs, todos,
   opensearch ingest/enrich, windows-triage). Tell me the plan before acting.
4. DRIVE, turn by turn: take ONE action, then tell me exactly which portal tab/row to check
   (e.g. "ingested X via opensearch_* → check Timeline/Backends", "recorded finding F-… → check
   Findings", "added IOC 185.66.0.12 → check IOCs"). I confirm it appears (or flag a mismatch),
   then you do the next. Watch for MCP errors or portal contract 4xx/5xx — those are the gaps we're
   hunting.
5. Build a small realistic investigation thread on ROCBA: a few findings (with observation /
   interpretation / justification), supporting timeline entries, 1–2 IOCs, a TODO — so I can then
   exercise the examiner workflow against REAL agent-created data (review, stage/approve, the F2
   immediate-Approve, Commit-to-record re-auth, custody verify/seal).

Division of labor: you = MCP actions (ingest/record/enrich); I = portal monitoring + examiner-side
testing. Coordinate per action: act → point me to the portal location → I confirm → next.

Guardrails: live TEST VM, data is regenerable — freedom to ingest/act/troubleshoot to make this
work; no destructive host/evidence ops beyond the case workflow; never paste secrets/tokens into
docs or GitHub; main stays clean (work on portal-v3 only). If a writeable tool is missing or a
portal surface doesn't update, that's a FINDING — log it (PORTAL_V3_EXTENSION_BACKLOG.md B-series,
or a P3.5 bug) instead of forcing it.

Still ahead after this (not blocking): extension backlog B1 (fabricated AgentActivityFeed) + B2
(commit-badge poll-staleness); Phase A (fresh-install install.sh end-to-end); P4 PR (only when I
ask).
```

---

## Notes for the driver (me, next session)
- Case-scoped tools (case_info, opensearch_*) require the agent principal be a MEMBER of the active
  case; the token was minted while ROCBA was active, so membership should hold. Reference/baseline
  tools (kb_*, capability_guide, wintriage_*) work regardless.
- A single broken backend can take down the whole `tools/list` (see [[project_lv1_live_test]]). If
  the surface looks empty/partial, check gateway health (`/api/v1/health`) and the offending backend.
- Health/curl from host: `curl --cacert ~/.sift-vm-ca-192.168.122.81.pem https://192.168.122.81:4508/api/v1/health`.
- This is the test that finally exercises the real portal write-path — the case was empty in the
  read-only pass, so expect to discover wiring gaps between MCP writes and portal reads.
