# Next Session — Rocba Case + MCP QA (handoff)

Paste the "PROMPT" block at the bottom to resume. Everything referenced is durable on disk / in the case.

## State as of 2026-05-29 (updated)
- **Mode:** Case-led; log MCP friction (don't stop to fix unless blocking). Solving the SANS
  "Stark Research Labs / Fred Rocba" case AND probing the MCP as the autonomous DFIR agent.
- **Case:** `rocba-drive-20260526-1417`, phase REPORTING, host `srl-forge`. 28 findings
  (26 DRAFT, 2 APPROVED). **Do NOT generate_report() until the deeper layer + audits resolve.**
- **Durable artifacts (host repo /home/yk/AI/SIFTHACK/sift-mcps):**
  - `audit-mrc-rdp-2026-05-29.md` — NEW. Full MRC/RDP audit memo (read this).
  - `mcp-qa-friction-log.md` — QA findings F-001..F-015 (F-011..F-015 added this session).
  - `NEXT-SESSION.md` — this file.
  - TODOs: -001 (A, DONE), -002 (B, ready), -003 (C, ready+reinforced), -004 (Audit: part 1 DONE, part 2 open).

## What's confirmed / staged
- **THREAD A — DONE (F-hermes-agent-001, HIGH):** Fred's laptop was a beachhead; after Nov 14 exfil the
  attacker RDP-pivoted into base-rd-08.shieldbase.lan (172.16.6.18) using Fred's saved domain creds (frocba).
- **AUDIT part 1 — DONE (F-hermes-agent-002, HIGH):** The Nov 16 02:31 Magnet RAM Capture (MRC.exe) was
  **LOCAL physical-console activity, NOT an attacker RDP session.** Refutes F-claude-004/012/013;
  refines F-lms-001. Evidence: (1) NO Type-10 RDP logon on Nov 16 — last remote RDP was Nov 14 12:52;
  (2) Nov 16 02:29:36 EID 4778 = `SrcIP: LOCAL` (vs Nov 14 = 52.249.198.56/cobra); (3) MRC PID 29440,
  PPID 7464=explorer.exe, SessionId 1, from D:\Tools; (4) ArbcoCircus (D:) is a PHYSICALLY-attached USB
  (WPD FriendlyName ArbcoCircus, VEN_IS917/INNOSTOR SN 201207220009, USBSTOR + \DosDevices\D:), so RDP
  drive-redirection is mechanically impossible. **Deeper layer:** intrusion is all REMOTE RDP, but a
  remote attacker can't insert a USB → a PHYSICAL-ACCESS actor was at SRL-FORGE Nov 10 12:49 (before any
  IR trigger, with a BitLocker key in a `secret key` folder) and Nov 16. Attribution OPEN. This is the
  Thread-C (insider/physical) signal.

## NEXT ACTIONS (priority order)
1. **TODO-004 part 2 — EDT/UTC normalization sweep.** Re-check every timing claim across findings for
   TZ consistency (Nov 13 ~22:42 EDT = Nov 14 03:42 UTC). Cheap, gates report quality.
2. **THREAD B (free — enrichment COMPLETE, 1,234 docs stamped, TODO-002):** harvest `threat_intel`
   verdicts to name the actor behind Azure 52.249.198.56 / WIIT-AG DE 81.30.144.115 / Verizon
   174.196.200.9 (note: 213.202.233.104 = NTLM RDP brute-forcer, refined in F-hermes-agent-002).
   Use lookup_ioc / search_threat_intel.
3. **THREAD C (insider/physical — TODO-003, now reinforced):** who is the physical-access actor? Tie to
   Fred's personal accounts as exfil DESTINATION vs conduit; the Nov 10 `srl-helpdesk@outlook.com` RDP
   from 174.196.200.9 — legit helpdesk or attacker account? Was anyone physically present Nov 10/16?
4. **USN+MFT files-landed** (still not indexed): MFTECmd on $J/$MFT, ingest, query attack windows for
   files created/written/DELETED. Answers "what landed / what got wiped."
5. **bulk_extractor on Rocba-Memory.raw** — DEPRIORITIZED. Run only for CARVING value (email/url/domain
   → feeds B/C), NOT as BitLocker-key proof (FVEK is always resident on an unlocked volume → proves nothing).
6. Can't reject/supersede the 3 wrong DRAFTs via MCP (friction F-015) — flag for human `agentir` reject.

## MCP gotchas to carry (so you don't re-hit them)
- **F-011 (date-range broken):** Lucene `Timestamp:[a TO b]` on hayabusa returns 0 silently (field is
  text). To time-bound: pull with `fields=` + filter dates in python, or use idx_timeline. evtx has a
  real `@timestamp`.
- **F-013/F-014:** big idx_search dumps blow the token cap; `size` is ignored. Always pass `fields=`
  (e.g. `Timestamp,EventID,Details,RuleTitle`) and `compact=true`; scope with `index=`.
- **F-012:** idx_search `index=` needs the FULL name `case-rocba-drive-20260526-1417-<artifact>-srl-forge`,
  not the short token idx_case_summary shows.
- **F-001:** list_existing_findings has no compact mode — it auto-saves to a file; parse with python
  (`json.loads(data[0]['text'])['findings']`).
- **F-003:** event.code is empty for Hayabusa docs — use `EventID:` (string). Hayabusa uses `EventID`
  + `Channel`; native evtx uses `event.code` + `winlog.channel`.
- Output discipline: pipe big tool output to file, then grep/python — never paste full output into reasoning.

---
## PROMPT (paste to resume)
Resume the Rocba case + MCP QA, case-led mode. Read audit-mrc-rdp-2026-05-29.md, NEXT-SESSION.md, and
mcp-qa-friction-log.md, then call workflow_status + manage_todo(list,all) + idx_case_summary to reload
state. Threads A (shieldbase pivot, F-hermes-agent-001) and the MRC audit part 1 (F-hermes-agent-002:
Nov 16 RAM capture was LOCAL/physical, not attacker-RDP — corrects F-claude-004/012/013) are DONE & staged.
Continue with NEXT ACTIONS: (1) TODO-004 part 2 EDT/UTC normalization sweep; (2) Thread B attribution
harvest (enrichment is complete — query threat_intel verdicts, lookup_ioc/search_threat_intel for
52.249.198.56 / 81.30.144.115 / 174.196.200.9; 213.202.233.104 is a brute-forcer); (3) Thread C
physical-access/insider — who plugged in ArbcoCircus Nov 10/16, and is srl-helpdesk@outlook.com legit?
Mind the MCP gotchas (F-011 date-range broken → use fields= + client-side filter or idx_timeline;
always pass fields= + compact=true + full index= name; list_existing_findings dumps to file).
Do NOT generate_report() until the deeper layer + audits resolve. Keep logging MCP friction.
