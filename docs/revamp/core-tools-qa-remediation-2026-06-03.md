# Core MCP Tools — QA Remediation (2026-06-03)

Source of truth: a live Hermes / gpt-5.5 forensic-agent session
("SIFT MCP Forensic QA Assessment", session `20260603_040135_a160dd`) that
exercised the aggregated `mcp_sift_protocol_*` surface against case
`rocba-exfiltration-20260602-1245` and reported contract, context, and
provenance defects. Each item below is a **root-cause** fix with a regression
test in `packages/sift-gateway/tests/test_qa_regressions.py`.

All live agent-facing core tools are the in-process `sift-core` tools defined in
`packages/sift-core/src/sift_core/agent_tools.py` (default `backends: {}`); the
separate `forensic-mcp` stdio server is not registered by default but was kept
in sync.

## Fixed

1. **`manage_todo` create/add contract mismatch (tool was unusable).**
   Schema advertised `action="create"` but the handler only accepted `"add"`,
   so `create` was rejected by the backend and `add` was rejected by the schema
   enum — TODO creation was impossible. Handler now accepts `create` (canonical)
   with `add` as a documented alias; schema/description/error message all agree
   on `create`. `agent_tools.py::_manage_todo`, `forensic_mcp/server.py`.

2. **`suggest_tools` never resolved advertised artifact names.**
   `get_artifact()` needs the file-stem id (`event_logs_security`) but the miss
   fallback advertised display names (`Security Event Log`) the resolver could
   not consume. Added `loader.artifact_catalog()` ({id, name, aliases}) and a
   normalized resolver (`discovery.py::_resolve_artifact_ids`) that accepts
   display name, stem, or alias (case/punctuation-insensitive, plus token-subset
   fallback). Misses now advertise `{id, name}` pairs that resolve.

3. **Internal errors masqueraded as "unknown tool run_command".**
   A `KeyError` raised *inside* a core tool escaped `call_core_tool` (it caught
   only `ValueError/OSError/RuntimeError`) and the gateway's
   `except KeyError -> "unknown tool"` mislabeled it. `call_core_tool` now
   converts any in-tool exception to a structured `{success:false, tool, error}`
   envelope; the only genuine "unknown tool" path is the pre-dispatch
   `name not in _SPECS_BY_NAME` check.

4. **`preview_lines` did not cap inline output (context bloat).**
   Output under the 10 KB response budget was returned in full regardless of
   `preview_lines`. `generic.run_command` now treats `preview_lines` as
   authoritative: caps inline stdout to N lines and reports `stdout_truncated`,
   `stdout_returned_lines`, `stdout_total_lines` (full output still on disk via
   `full_output_path`).

5. **Compound-command provenance showed only the last segment.**
   For `a && b && c`, the aggregated result kept only the last pipeline's
   `command`. Now records `original_command` (exact string) and a `command`
   spanning every executed stage (`{argv, redirects}`).

6. **Examiner identity flipped between success and error.**
   `run_command` error paths omitted `examiner=`, so blocked calls fell back to
   the config examiner (`alice`/`examiner`) while successes showed the caller
   (`hermes-default`). All `build_response` calls now pass the effective
   examiner.

7. **Instructions claimed `python3` was runnable.** GATEWAY instructions said
   tools "including ... python3" are available, but interpreters are on the deny
   floor. Replaced with accurate run_command grammar/policy (string supports
   pipes/`&&`/`||`/`;`/redirects; shells & interpreters blocked; `shell=False`).

8. **`awk` description overstated risk / understated control.** It said
   "audit logging is the primary control" while `system()/getline/pipe` are
   actually blocked in awk program text. Corrected the catalog description; added
   an end-to-end test proving `awk 'BEGIN{system("id")}'` is blocked.

9. **`capability_guide` looked broken when empty.** It is add-on-only but read
   as a failure next to a "ready" environment_summary. Description now states
   add-on-only scope; result carries `scope` and, when empty, a `note` that this
   is expected; `case_status` investigation_guidance now routes core-tool
   discovery to `list_available_tools`/`environment_summary`.

10. **Empty/invalid filters stranded the agent.** `list_available_tools` with an
    unknown category now returns `available_categories`; `run_command` schema
    fields (`preview_lines`, `save_output`, `timeout`, `input_files`, …) now have
    descriptions so the contract is explicit in `tools/list`.

11. **`get_tool_help` shallowness.** Added an accurate `usage_hint` pointing the
    agent to `run_command(['<bin>','--help'])` for the full CLI, without
    fabricating per-tool docs.

## Already fixed before this round (verified, transcript was stale)

- `case_file_structure` returns a slim summary + `full_tree_path` (no longer the
  full 84-dir dump the transcript showed).
- `environment_summary` / `list_existing_findings` return slimmed payloads.

## Deferred (not bugs — recommendations)

- **Actor vs case_examiner audit model.** The agent suggested separating
  `actor` (who ran) from `case_examiner`. The immediate inconsistency is fixed;
  a richer identity schema is a larger audit-format change, intentionally not
  done here to avoid churn.
- **Deeper `get_tool_help` content** for EvtxECmd/vol3/RECmd/log2timeline/MFTECmd
  is forensic-knowledge data authoring, not a code defect. The code path already
  surfaces caveats/quick_start/field_meanings when present.

## Verification

`packages/sift-gateway/tests/test_qa_regressions.py` (12 tests) pin every fix.
Full suites green: sift-core 326, sift-gateway 147, forensic-mcp 20,
opensearch-mcp 973 (+71 skipped), windows-triage 11, case-dashboard 292.
No new ruff findings introduced (pre-existing repo lint debt unchanged; ruff is
not part of the gate).
