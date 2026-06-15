# Known Limitations and Areas of Improvement

Status: archival — partially superseded. Updated by BATCH-RG1 (2026-06-13):
- Ingest mount privilege row updated: service now runs as `sift-service` (HR3/BATCH-HR3).
- RAG scope introspection row updated: `rag_search_case` removed; RAG is `kb_*` via add-on.
- See `docs/operator/maintenance-guide.md` for the current operational state.
Last updated: 2026-06-13 (RG1 corrections applied on top of original 2026-06-10 entry).

## Current Known Limitations

| Area | Limitation | Demo impact | Improvement path |
| --- | --- | --- | --- |
| Re-auth | MVP uses a local HMAC/password bridge for sensitive portal actions. | Acceptable if explained clearly; not a custody bypass because Gateway still records the re-auth event and DB transition. | Move to Supabase password re-auth/session verification. |
| Re-acquisition click proof | The `violated -> sealed` re-acquisition path is deployed and route/unit tested, and live service-RPC proof exists, but the portal click path has not been rerun in this FRZ1 pass. | Do not present a live re-acquire click on the prepared Rocba case unless rerun on a throwaway file first. The custody story can show the already-retired ghost and re-acquired replacement. | Run the click proof on a throwaway case/file: seal small file, modify bytes, rescan to violation, re-seal with reason/HMAC, confirm gate clears. |
| Ingest mount privilege | Disk-image ingest needs root to mount (xmount/ewfmount/mount/losetup/qemu-nbd/modprobe nbd/partprobe/umount/fusermount). **RG1 (2026-06-13): RESOLVED in BATCH-HR3** — gateway/worker now run as the dedicated non-admin `sift-service` user with a narrow audited sudoers allowlist (`configs/systemd/sift-gateway.service`, `sift-job-worker.service`). The blanket `sansforensics` sudo is no longer used for service execution. Residual: per-exec kernel sandbox (bwrap/seccomp) still TODO (see IMP-FRZ1-10). | Residual per-exec sandbox only | Per-exec bwrap/LXC sandbox (IMP-FRZ1-10). |
| Installer re-run | A full destructive `./install.sh` re-run has not been exercised on a throwaway VM. Source now installs `ripgrep`/`acl`, repairs `pyewf` after `uv sync`, renders both Gateway and worker unit files, and wires the runtime + ingest sudoers helpers. | None for the live demo if the prepared VM is used. Risk is reinstall/idempotency drift on a fresh VM. | Run a destructive idempotency pass on a throwaway VM before claiming installer freeze complete. |
| Offline memory symbols | Volatility now works unprivileged and is live-proven on `Rocba-Memory2.raw`, but a cold offline VM may need Microsoft symbols already cached or staged. | Online/cached demo is OK. Fully offline demo should warm or bundle symbols first. | Bundle common Windows ISF symbols into the install image or pre-warm the case symbol cache before the demo. |
| run_command progress stderr | Durable forensic tools can put carriage-return progress spam in stderr; output is capped but still noisy. | Cosmetic/context cost only. It does not expose secrets or block the demo. | Filter progress lines in the worker output path while preserving real errors. |
| Pre-context denials | Some pre-context denials remain Gateway-local security telemetry, not `app.audit_events`. | Accepted MVP behavior; it does not affect authorized demo actions or report eligibility. | Add a DB projector for attributable pre-context denials. |
| Agent scope introspection | **RG1 (2026-06-13): `rag_search_case` removed.** RAG is now served by the `forensic-rag-mcp` add-on backend (`kb_search_knowledge` etc., namespace `kb`). Scope grammar is unchanged: agent needs `mcp:*` or `namespace:kb` or `tool:kb_search_knowledge` etc. The agent still cannot self-inspect its granted scopes. | Operator must verify the issued scope set covers `kb_*` tools. | Surface issued scopes or add a catalog self-check tool. |
| RAG authority | Shared forensic knowledge rows are case-neutral (`case_id NULL`). | Correct for reference grounding; not case evidence. The agent must not cite RAG as proof of what happened in the case. | Add case-derived chunks with evidence provenance after ingest. |
| OpenSearch profile | Single-node OpenSearch can report yellow health. | Acceptable if indexing/search works. | Use a multi-node or replica-adjusted production profile. |
| Agent-visible file mirrors | `evidence_info` listing and `record_finding` artifact audit checks are DB-backed now. Residual agent-visible context such as `case_info.file_structure`, `agent/findings_list.json`, grounding-score source checks, and some audit summaries can still reflect file mirrors or saved snapshots. | Low if the demo treats DB-backed `case_info` counters, `evidence_info`, findings list, and report authority as the source of truth. | Continue moving advisory/snapshot fields to DB-derived reads, or label them explicitly as snapshots. |
| Custody event vocabulary | Re-acquisition currently records a `MANIFEST_SEALED` custody event with `details.reacquired=true`. | Demoable, but less legible than a dedicated event type in a courtroom appendix. | Add an `EVIDENCE_REACQUIRED` enum value and update report/API wording. |
| Per-exec sandboxing | `run_command` uses the restricted runtime user and case write jail, but not a per-exec bwrap/LXC namespace with seccomp/netns. | Accepted MVP caveat; it does not solve ingest mount privilege by itself. | Add per-exec sandboxing for deeper defense in depth. |

## Improvement Backlog

| ID | Priority | Area | Improvement | Owner batch | Status |
| --- | --- | --- | --- | --- | --- |
| IMP-FRZ1-01 | P1 | Portal principal UI | Show token type, display name, active/expired/revoked status, TTL remaining, and a revoke button that disables/dims after successful revoke. | BATCH-FRZ1 | Done |
| IMP-FRZ1-02 | P1 | Service identity | Move gateway/worker to a dedicated non-admin service user and enforce the narrow mount sudoers allowlist. **RG1 (2026-06-13): RESOLVED in BATCH-HR3** — services now run as `sift-service` (see `configs/systemd/sift-gateway.service`). | BATCH-HR3 | **Done** |
| IMP-FRZ1-03 | P1 | Installer | Add post-sync `pyewf` relink, `rg` install, and destructive throwaway-VM idempotency coverage. | Post-freeze hardening | Partial: source fixed; throwaway VM proof open |
| IMP-FRZ1-04 | P1 | Offline symbols | Bundle or pre-warm Windows ISF symbols for fully offline memory demos. | Post-freeze packaging | Open |
| IMP-FRZ1-05 | P2 | Output polish | Filter carriage-return progress spam from durable job stderr previews. | Post-freeze polish | Open |
| IMP-FRZ1-06 | P2 | Audit projection | Project pre-context denials into DB audit authority. | V1 audit hardening | Accepted deferred |
| IMP-FRZ1-07 | P2 | Agent ergonomics | Surface granted MCP scopes or add a catalog self-check. | Post-freeze autonomy | Open |
| IMP-FRZ1-08 | P2 | Case RAG | Add case-derived RAG chunks with evidence provenance. | Post-freeze RAG | Open |
| IMP-FRZ1-09 | P3 | Custody wording | Add a dedicated `EVIDENCE_REACQUIRED` event type. | Post-freeze custody | Optional |
| IMP-FRZ1-10 | P3 | Execution sandbox | Evaluate bwrap/LXC per-exec sandboxing for `run_command`. | Post-freeze security | Optional |

## Resolved For Freeze

- DB-backed `evidence_info` listing is live-proven on the demo case.
- `record_finding` artifact/audit validation accepts DB transport audit IDs in
  DB-active mode.
- `case_info` finding counters are DB-authoritative.
- Portal login, local HMAC verification, fresh agent issuance, and 48-hour
  token TTL are live-proven.
- Portal principal/session table now shows Supabase JWT token type, display
  name, active/expired/revoked state, TTL remaining, scopes, and disables/dims
  revoke after success; legacy PR02 token controls are no longer shown in the
  normal Settings page.
- **RG1 (2026-06-13): `rag_search_case` removed** — replaced by `kb_search_knowledge`
  and sibling `kb_*` tools in the `forensic-rag-mcp` add-on (BATCH-OSX-RAG / NW2).
  The original 13-tool catalog count is now stale; add-on tool count depends on which
  backends are registered.
- Volatility cache/HOME/XDG issues are resolved for `Rocba-Memory2.raw`.
- Logical E01 triage is demo-ready with direct `fls`.
- Large command outputs can be saved under `agent/run_commands/...` and cited by
  relative output refs.

## Demo Caveat Rules

- Caveats are acceptable only when they are explicit, bounded, and do not break
  the security thesis.
- Any caveat that weakens MCP-only autonomy, custody, report eligibility, or
  secret isolation must be fixed or called out as a blocker before freeze.
