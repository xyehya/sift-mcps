# Validation — Cluster ARCHIVE (extraction containment)

> Validator agent: sec-archive (Opus 4.8, xhigh). Read-only. Validated against current HEAD `93f8999` (183 commits past scan base `b995491`). Codex line numbers re-located. No source modified. Empirical extractor behavior was tested live on this host (GNU tar 1.35, 7-Zip 26.01, Python 3.14) replicating the exact commands the code issues.
>
> NOTE: persisted by the orchestrator — sec-archive's security-reviewer contract is hard read-only (it does not write report files), so it returned this verdict verbatim for the orchestrator to save.

## Summary table

| Candidate | Codex verdict | Current status | Current severity | Confidence | Already-fixed-by | Fix effort |
|---|---|---|---|---|---|---|
| DSS-CAN-008 (tar ingest) | partial/med | PARTIALLY-FIXED | Low | high | extractor defaults + existing post-walk (containers.py:76-82) | M (shared) |
| DSS-CAN-009 (memory 7z) | partial/med | PARTIALLY-FIXED | Low–Medium | high | extractor defaults only | M (shared) |
| DSS-CAN-017 (generic 7z/zip) | partial/med | PARTIALLY-FIXED | Low–Medium | high | extractor defaults only | M (shared) |
| **Cross-cutting (all 3)** | — | **STILL-VALID** | **Medium** | high | nothing | M |

Cross-cutting Medium = (1) decompression-bomb / disk-exhaustion DoS — NO size/entry/ratio cap, no timeout on the generic path; and (2) all path-escape containment is delegated to external-binary version defaults with no application guarantee, across 3 divergent code paths.

---

## Shared architecture (applies to all three)

`containers.py:45 extract_container(path,dest,password)` is the single chokepoint for the generic/disk-archive path and dispatches:
- `.zip/.7z` → `_extract_7z` (containers.py:58) → `subprocess.run(["7z","x",str(path),f"-o{dest}","-y"])`, raises only when `returncode > 1`. **No member preflight, no post-check, no size cap, no timeout.**
- `.tar/.tar.gz/.tgz` → `_extract_tar` (containers.py:73) → `subprocess.run(["tar","xf",...,"-C",dest], check=True)` then a post-extraction `os.walk` that resolves each **file** and rejects entries not `is_relative_to(dest)`. **No preflight, no size cap, no timeout; post-walk iterates only `files` (dir-symlinks skipped).**

`ingest_cli.py:660,744-745` (cmd_scan) calls `extract_container` for disk/Velociraptor archives → **DSS-CAN-008 and DSS-CAN-017 are literally the same function**, only the format branch differs. Extracted output lands under `make_ingest_tmpdir` = `SIFT_CASE_DIR/tmp/ingest-…` (inside the case jail).

`ingest_cli.py:2273-2296` (cmd_ingest_memory) is a **separate, divergent** `7z x` into `tempfile.mkdtemp(prefix="sift-mem-")` (= system `/tmp`, NOT the case jail), `check=True`, `timeout=600`, then selects the image by suffix via `iterdir()` with **no `.is_file()` / realpath check** → DSS-CAN-009. Dispatched as a subprocess by `server.py:4094 idx_ingest_memory`.

**Runtime posture (blast-radius driver):** all extraction runs in `sift-opensearch-worker@.service` as the gateway service user, carrying `CAP_SYS_ADMIN` + `sudo -n` to root for mounts, and — per the FUSE constraint — **no ProtectSystem / no private mount namespace / no PrivateTmp** (host namespace). So an extraction write-escape would land on the real host FS owned by the service user (incl. the install tree at `SIFT_MCPS_ROOT`), and a bomb has no PrivateTmp/quota wall. The only thing standing between a malicious archive and that surface today is the external extractor binary's version-specific defaults.

## Empirical extractor proof (this host; replicate the deployed commands)

| Vector | GNU tar 1.35 (`tar xf -C dest`) | 7-Zip 26.01 (`7z x -odest -y`) |
|---|---|---|
| `..` member | REFUSED: "Member name contains '..'" → **exit failure → check=True raises** | silently sanitized into dest (no error, rc=0) |
| absolute path | leading `/` stripped → contained in dest | sanitized/contained |
| symlink write-through (abs + relative) | symlink created in dest, write-through REFUSED ("Cannot open: Not a directory") → **exit failure → raises** | absolute symlink **re-rooted under dest** (broken), write-through fails → "Archives with Errors" → raises |
| hardlink → outside / `../sealed_evidence` | targets stripped, link fails ("No such file or directory") → **exit failure → raises** | n/a (zip hardlinks rare) |
| device/FIFO nodes | non-root + no CAP_MKNOD ⇒ device members can't be created; FIFO contained | same |
| ownership / setuid restore | non-root ⇒ ownership ignored; mode via umask 0077; setuid-to-self = no gain | same |
| **decompression bomb (size/ratio)** | **NO LIMIT** (no timeout) | **NO LIMIT** (generic); memory path has only `timeout=600` |
| leftover outward symlink (no write-through) | created in dest, harmless; downstream `safe_rglob`→`rglob` does not recurse symlinked dirs (Py3.14) | re-rooted broken link |

**Conclusion:** on the deployed extractor versions, every classic write-escape (zip-slip / tar-slip / symlink/hardlink traversal / abs path) is blocked by the binaries themselves — NOT by application code (except tar's redundant post-walk). Two genuine residuals remain: the **decompression-bomb DoS (unmitigated)** and the **architectural fragility** of trusting external-binary version defaults across three divergent paths.

---

## DSS-CAN-008 — tar evidence archives validated only after extraction
**Current code:** `containers.py:73-82` (`_extract_tar`), called from `ingest_cli.py:745` (codex cited ingest_cli.py:719-738). **Drift:** ingest_cli.py changed +144 (worker-OOM RAM preflight, hostname derivation, F8 envelope) — none touched extraction; containers.py UNCHANGED since b995491.
**STATUS: PARTIALLY-FIXED — severity Low.** The post-extraction `os.walk` containment check Codex flagged "only after extraction" is present and correct for file members; combined with GNU tar 1.35 refusing `..`/symlink/hardlink escapes (proven above, all raise via `check=True`), there is no currently-reachable write-escape. Residuals folded into the cross-cutting Medium: no decompression-bomb cap, no timeout, no member preflight (containment depends entirely on the tar binary's version), post-walk skips dir-symlinks (harmless given rglob non-recursion).

## DSS-CAN-009 — memory ingest separate unchecked 7z path
**Current code:** `ingest_cli.py:2273-2296` (the actual `7z x`); dispatched by `server.py:4094 idx_ingest_memory` (codex cited server.py:3745-3925 — that region is now the memory tool handler; extraction lives in the CLI subprocess). **Drift:** server.py +337 (M-INGSTATUS/M-HOSTNAME/RAM preflight) — relocated/added checks but did not touch the 7z extraction; still its own divergent path.
**STATUS: PARTIALLY-FIXED — severity Low→Medium.** No currently-reachable write-escape (7z 26.01 re-roots/sanitizes, `check=True` raises on any error). But this path is the worst-shaped: (a) duplicates extraction logic instead of using `extract_container`; (b) extracts to system `/tmp` outside the case jail (escapes the agent_runtime ACL/disk-accounting boundary — a posture regression vs the generic path); (c) no post-extraction containment re-check; (d) selects the memory image by suffix via `iterdir()` with no `.is_file()`/realpath guard (a re-rooted symlink named `x.raw` would be picked and read by Volatility — low impact but sloppy); (e) only `timeout=600`, no size cap.

## DSS-CAN-017 — generic zip/7z extraction lacks app containment
**Current code:** `containers.py:23-33` (detect) + `:45-70` (extract/`_extract_7z`) — codex's exact cited region, UNCHANGED since scan.
**STATUS: PARTIALLY-FIXED — severity Low→Medium.** No currently-reachable write-escape (proven). Residuals: `_extract_7z` has NO containment check at all (neither preflight nor post-walk — unlike the tar branch); it **swallows 7z exit-code 1 warnings** (only `>1` raises) — exactly Codex's "treat dangerous warnings as failure" point, and inconsistent with the memory path's `check=True`; no size/entry/ratio cap; no timeout.

---

## FIX APPROACH (secure-by-design, one shared safe extractor)

**Root cause:** containment is delegated to external-binary version defaults across three divergent code paths, with no application-level guarantee and no resource bound.

**Change — make `containers.extract_container` THE single hardened entry point and route all three callers through it:**
1. **Member preflight (pre-write):** before invoking the binary, enumerate members and reject the dangerous classes. For tar use Python `tarfile.getmembers()` (the well-vetted PEP-706 `data` filter logic: reject absolute paths, any `..` component, symlinks/hardlinks whose resolved target leaves dest, char/block/FIFO/contiguous types, setuid/setgid bits). For 7z/zip use `7z l -slt` and reject entries with `..`/absolute names or symlink attributes. Keep the system binary for the actual extraction (forensic-scale perf + format coverage — the reason tarfile/zipfile aren't used as the extractor) — preflight is cheap and runs first.
2. **Resource caps (anti-bomb):** from the same listing, enforce a configurable max total uncompressed bytes, max entry count, and max compression ratio; add a `subprocess` timeout to BOTH tar and 7z. Fail before extraction when the declared totals exceed caps; also add a free-space check against `os.statvfs(dest)`.
3. **Warning-as-failure:** treat 7z rc==1 as failure (or parse the warning class) — align generic path with the memory path's `check=True`.
4. **Post-extraction re-check (defense-in-depth):** keep/generalize the existing `os.walk` realpath containment, extended to dirs and symlinks, for BOTH formats.
5. **Route memory through it:** replace `ingest_cli.py:2273-2296` with `extract_container(...)` into a `make_ingest_tmpdir`-style **case-jail** dir (not `/tmp`), then select the image with `.is_file()` + realpath-under-dest.

**Placement:** all of it in `packages/opensearch-mcp/src/opensearch_mcp/containers.py` (already the shared module and already imported by the generic path) — `_extract_7z`/`_extract_tar` become internal; `extract_container` gains preflight+caps+post-check. One module, one chokepoint.

**Why it preserves invariants:** pure filesystem-safety inside the first-party opensearch worker; touches no DB creds (DB-authority intact), runs post-evidence-gate on already-sealed-but-attacker-controlled bytes, complements (doesn't replace) the least-priv sandbox and the DSS-CAN-007 mount broker. **Surfacing:** a rejected archive must surface through the EXISTING worker failure envelope — `write_status(status="failed", error=…)` / the ingest `*Out` status path — not just raise in the subprocess (heed the surfacing lesson); add a `containment_rejected`/`reason` field and register it in `SURFACE_OPTIONAL_KEYS` if you expose it.

**Test strategy:**
- Unit fail-on-revert fixtures (opensearch-mcp tests): malicious tar (symlink write-through, dotdot, abs, hardlink-to-outside, device member) + malicious zip (dotdot, symlink) + a declared-size bomb fixture. Assert `extract_container` raises an **application-level** containment/cap error and that nothing was written outside dest. Critical: assert the APP rejects (preflight/cap fires) — not merely "no escape" — so the test fails-on-revert if someone deletes the preflight (today these would pass purely on binary defaults, which is exactly the gap).
- Surface/conformance test: a rejected ingest yields a `failed`/containment status through the worker `result_public` envelope.
- Live deploy-and-prove on the VM: register a crafted malicious archive + a bomb archive as sealed evidence under a throwaway case, run ingest, confirm clear rejection status and that nothing was written outside the case tmp and disk was not exhausted.

**Alternatives rejected:** (a) pure `tarfile.extractall(filter='data')`/`zipfile` as the extractor — loses forensic-scale perf and 7z/split/encrypted format coverage; use it for preflight only. (b) three separate patches — divergence IS the root cause; the memory path already drifted (own 7z, `/tmp`). (c) throwaway-namespace/container sandbox per extraction — heavier; the worker is already namespace-constrained by FUSE; preflight + caps + quota'd scratch is proportionate now.

**Cross-cluster dependency:** EXEC **DSS-CAN-007** (mount-capable worker) — extracted disk images are mounted at `ingest_cli.py:767 mount_image`. The shared safe_extract guarantees the to-be-mounted image path stays in the case jail (no symlink swap to an outside image) and the bomb/quota guard protects the same worker DSS-CAN-007 governs; safe_extract is the hardening layer *beneath* the mount broker.

**Open question for operator:** confirm the pinned tar/7z versions shipped/locked on the official SIFT VM image (containment currently rests on them); and choose the bomb caps (suggest max-uncompressed and max-ratio tuned to real evidence-archive sizes, made configurable).
