# Tool Availability & Catalog Plan

> Covers: install.sh (`install_host_prereqs`, `install_zimmerman_symlinks`), packages/sift-core/src/sift_core/execute/{environment.py, security_policy.py, catalog.py, tools/discovery.py}, packages/sift-core/data/catalog/**
> Class: living-plan
> Last validated: cb2993d (2026-06-18)
> Sources: live SSH inventory (sansforensics@192.168.122.81), live gateway `capability_guide`/`get_tool_help('inventory')`, code-audit of the run_command catalog/allowlist/resolution path.

**Premise:** default SANS SIFT already works for our tests. This track is **complementary** — it (a) repairs resolution defects, (b) installs genuinely-absent cataloged tools *fail-safe / non-blocking*, and (c) adds valuable SIFT tools that are present but not yet exposed. No change may make a working install fail.

---

## 1. How tool availability actually works (verified)

A tool is usable by the agent only when THREE conditions align:

1. **Cataloged** — entry in a `packages/sift-core/data/catalog/*.yaml` file (enriched help + correct `binary`). Lookup key = `name`; real argv[0] = `binary` (defaults to name). `catalog.py:53-72,108-147`.
2. **Admitted by policy** — argv[0] **basename** is not matched by a `DENY_FLOOR` glob, then either allowlisted (`MVP_FORENSIC_ALLOWLIST`, `security_policy.py:136-247`) or run under the default `unlisted_policy: contained` (security_policy.py:252 — unlisted ⇒ *contained*, NOT rejected). Basename-only check; **no `.py`/script/shebang rejection** (`security.py:905,912,917-921`).
3. **Resolvable** — `find_binary(binary)` returns a path, else run_command dies `ValueError: not found` (`security.py:924-926`). Same resolver feeds the availability flag (`discovery.py:163,194,279`), so the flag is honest (no false positives) but **fails closed** (false negatives for subdir/`/opt/*/bin` installs).

`find_binary` (`environment.py:46-65`): `shutil.which(name)` → else fallback dirs `[/usr/local/bin, /opt/zimmermantools, /opt/volatility3, /opt/hayabusa]`, checking only `Path(d)/name` `is_file()&X_OK`. **Gaps:** (a) never checks `Path(d)/name/name` → EZ subdir layout unresolvable; (b) case-sensitive → uppercase catalog name misses lowercase wrapper; (c) fallback omits `/opt/*/bin`.

---

## 2. Existing-vs-missing matrix (task 3)

| Tool(s) | Bucket | State on VM | Cause | Action |
|---|---|---|---|---|
| **yara** | A | absent (libyara10+python3-yara only, no CLI) | installer never installs it; SIFT image lacks CLI | fail-safe `apt install yara` (Candidate 4.5.0) |
| **tshark** | A | absent (wireshark libs present, no CLI) | not installed | fail-safe `apt install tshark` (4.2.2) |
| **binwalk** | A | absent | not installed | fail-safe `apt install binwalk` (2.3.4) |
| **zeek** | A′ | absent | no apt candidate | defer (own repo) or skip; warn-only |
| **PECmd, SrumECmd** | A′ | absent from /opt/zimmermantools | not in this SIFT EZ bundle | best-effort `Get-ZimmermanTools` (pwsh present at /opt/microsoft); non-blocking |
| **RECmd, SQLECmd** | B | binary present at `/opt/zimmermantools/<T>/<T>`; working **lowercase** `recmd`/`sqlecmd` wrappers exist; our Jun-15 **uppercase dir-symlink** is broken | (1) our `install_zimmerman_symlinks` `test -x` true-for-dir bug; (2) `find_binary` subdir + case gaps | fix symlink → inner binary; harden `find_binary` |
| **evtx_dump** | B | absent as `evtx_dump`; present as `/usr/local/bin/evtx_dump.py` → `/opt/python-evtx/bin/evtx_dump` | name/`invoke_as` mismatch | set catalog/allowlist `evtx_dump.py` (or keep `evtxexport`, already works) |
| **vol3, volatility3** | C | absent as names; `vol` works | alias names, not real binaries | drop alias entries or `invoke_as: vol`; cosmetic |
| **tree** | C | absent | non-forensic | ignore (or trivial apt) |
| **hayabusa** | C | available (resolves via /opt/hayabusa fallback) | `/usr/local/bin/hayabusa` is a **dangling** symlink → /var/lib/sift/.sift/bin/hayabusa | cleanup the dead symlink |
| **dc3dd** | C-bug | n/a | cataloged in misc.yaml **AND** in DENY_FLOOR → can never run | remove from catalog (misleading) |
| Bucket-D set | D | present, uncataloged | see §3 | add the worthwhile ones |

---

## 3. Add-candidate proposals (task 8)

Bucket-D tools are Python-venv tools, each with a `/usr/local/bin` wrapper (⇒ on PATH ⇒ `find_binary` resolves via `shutil.which`). All proposed basenames are **DENY_FLOOR-glob clear** (none start `python*/perl*/ruby*/node*/lua*` or end `*sh`). They run **today** under `unlisted_policy: contained`; cataloging+allowlisting promotes them to enriched + normal.

### KEEP — High value, unique, read-only

| Catalog name | binary / invoke_as | category | DFIR value | notes |
|---|---|---|---|---|
| hindsight | `hindsight.py` (`-i` input) | browser | Chrome/Chromium/Edge history, downloads, cookies, autofill | **no overlap** with opensearch parsers; high agent value |
| pdfid | `pdfid.py` | malware | PDF structure/triage (JS, launch, embedded) | malware grounding |
| pdf-parser | `pdf-parser.py` | malware | PDF object/stream inspection | pairs with pdfid |

### KEEP — Medium value

| Catalog name | binary | category | notes |
|---|---|---|---|
| indxparse | `INDXParse.py` | filesystem | $I30 INDX slack → deleted-file recovery; unique vs EZ |
| list_mft | `list_mft.py` | filesystem | MFT listing (indxparse suite) |
| usnparser | `usnparser` (wrapper → usn.py) | filesystem | $UsnJrnl file-activity timeline. NB: catalog `binary` MUST be `usnparser` (the on-PATH wrapper); `usn.py` is NOT on PATH and would not resolve. |
| pe-scanner | `pe-scanner` | malware | PE imports/entropy/anomaly |
| packerid | `packerid.py` | malware | PE packer/compiler detection |
| sqlite-carver | `sqlite-carver` | recovery | deleted SQLite records (apps/browsers/chat) |
| page-brute | `page-brute` | malware | pagefile.sys YARA scan — **depends on yara (Bucket A)**; gate on yara install |
| mvt-ios | `mvt-ios` | mobile | iOS compromise check; `download-iocs` needs network — flag |
| mvt-android | `mvt-android` | mobile | Android compromise check; network flag as above |
| mac-apt | `mac_apt.py` (verified `/usr/local/bin/mac_apt.py → /opt/mac-apt/bin/mac_apt_git/mac_apt.py`) | macos | macOS artifact analysis; clean CLI entrypoint confirmed 2026-06-18. Positional usage: `input_type input_path plugin...`. |

### KEEP — Low value / overlap-tolerated

| Catalog name | binary | note |
|---|---|---|
| analyzemft | `analyzemft` | Linux-native $MFT parse; overlaps MFTECmd — keep as cross-check |
| evtx_dump | `evtx_dump.py` | EVTX→XML; overlaps EvtxECmd + opensearch ingest (this is also Bucket B) |
| pe-carver | `pe-carver` | carve PE from dumps (writes to agent dir) |
| idx-parser | `idx-parser` | Java IDX cache (web-exploit evidence) |
| usbdeviceforensics | `usbdeviceforensics` | USB device history from hives |

### REJECT (with reason)

| Tool | Reason |
|---|---|
| machinae | OSINT/IOC enrichment = **network egress** + overlaps the OpenCTI TI plane (one TI plane policy). Defer. |
| amcache (`amcache.py`) | overlaps opensearch amcache parser + AmcacheParser. |
| stix-validator, cybox-validator | dev/QA validators, not investigative analysis. |
| ioc_writer (`iocdump`) | OpenIOC conversion utility; low agent value. |
| 4n6-scripts bundle | grab-bag of niche mobile/misc `.py`; cherry-pick per-case later, not as a bundle. |
| imagemounter (`imount`) | wraps `mount`/`losetup` → DENY_FLOOR conflict; **operator-only**. |
| ufade | iOS **acquisition** — operator-side, outside agent scope. |

---

## 4. Fix spec (task 4 — for operator approval BEFORE task 5)

All installer tool work MUST be **best-effort / non-blocking** (warn-and-continue, never `die`).

**F-1 `install.sh` `install_zimmerman_symlinks` (install.sh:1057-1081).** Replace `test -x "$dir/$tool"` (true for dirs) with: link `$dir/$tool` only if it is a regular executable **file**; else if `$dir/$tool/$tool` exists (subdir layout) link the **inner** binary; else skip. Idempotent. Fixes RECmd/SQLECmd.

**F-2 `find_binary` (environment.py:46-65).** Add, in the fallback loop: also probe `Path(d)/name/name` (subdir layout). Optionally add `/opt/*/bin` glob to the fallback dirs. (Defense-in-depth; F-1 already fixes RECmd/SQLECmd via PATH.) Keep behavior fail-closed; add a focused unit test with a fake subdir tree.

**F-3 fail-safe complementary install (new `install.sh` helper).** Best-effort `apt-get install -y` for **yara, tshark, binwalk** (each guarded; warn on failure, never abort). zeek: attempt only if a candidate exists, else warn. This is the install-or-warn for cataloged-but-absent tools.

**F-4 `Get-ZimmermanTools` (best-effort).** Use pwsh (/opt/microsoft) or the dotnet fetch to pull PECmd/SrumECmd into /opt/zimmermantools, then re-run F-1 symlinking. Non-blocking; skip cleanly if pwsh/network absent.

**F-5 catalog cleanups.** Remove `dc3dd` from misc.yaml (DENY_FLOOR conflict); drop or `invoke_as: vol` the `vol3`/`volatility3` entries; set `evtx_dump` `invoke_as: evtx_dump.py`. Fix the dangling `/usr/local/bin/hayabusa` symlink (point at `/opt/hayabusa/hayabusa` or remove — `/opt/hayabusa` fallback already resolves).

**F-6 add cataloged tools (task 8 KEEPs).** New catalog YAML entries + allowlist basenames (incl. lowercase variants) per §3, gated by priority. page-brute gated on F-3 yara. mac-apt pending entrypoint confirmation.

**F-7 (optional) preflight honesty.** A post-install report of cataloged-but-unresolved tools so the operator sees the 3-state gap; optionally suppress the agent instruction for absent tools (e.g. don't teach `yara` when absent). Ties to Axis F (XYE-48/49).

**Validation per change:** `bash -n install.sh`; `uv run --extra dev --extra full pytest` for find_binary/discovery; `python3 scripts/validate_docs.py`; live re-check via `capability_guide`/`inventory` after applying to the VM (sanitized proof).

---

## 5. Operator decisions (resolved 2026-06-18)

1. **F-3 scope:** ✅ **Auto, fail-safe, every install** — best-effort apt-install yara+tshark+binwalk (warn-and-continue, never block); zeek warn-only/skip (no apt candidate).
2. **F-4 PECmd/SrumECmd:** ✅ **Document as operator-optional; do NOT auto-fetch.** Their output is already covered by opensearch ingest (`parse_plaso` prefetch, `parse_srum`).
3. **Add-candidate cut line:** ✅ **High + Med** this pass: hindsight, pdfid, pdf-parser, indxparse, usnparser, pe-scanner, packerid, sqlite-carver, page-brute (gated on yara), mvt-ios, mvt-android, mac-apt (confirm entrypoint). Low tier deferred.
4. **mvt network:** ✅ **Offline-check subcommands only** — no `download-iocs` egress; block network-fetching subcommands.
5. **F-2 `/opt/*/bin` glob:** ✅ **Add it** to `find_binary` fallback (future-proofs bucket-D resolution).

---

## 6. Implementation status (landed 2026-06-18, branch `fix/tool-availability-catalog`)

| Spec | Status | Notes |
|---|---|---|
| F-1 install_zimmerman_symlinks | ✅ | `test -f` + subdir `<Tool>/<Tool>` fallback; idempotent |
| F-2 find_binary | ✅ | probes `d/name` AND `d/name/name`; adds `/opt/*/bin` glob; fail-closed; 5 new unit tests (`test_find_binary.py`) |
| B1a catalog RECmd/SQLECmd | ✅ | `binary: recmd`/`sqlecmd` (lowercase dotnet wrappers on PATH) — resolves today |
| F-3 install_complementary_tools | ✅ | best-effort apt yara/tshark/binwalk; zeek warn-only; returns 0 always; core-block only |
| F-4 PECmd/SrumECmd | ⏭️ deferred | operator-optional (opensearch covers prefetch/SRUM) |
| F-5 cleanups | ✅ | `dc3dd` removed from misc.yaml; dangling `/usr/local/bin/hayabusa` repair in installer; `evtx_dump` cataloged (`evtx_dump.py`, timeline.yaml) |
| F-6 add tools | ✅ | 15 cataloged + allowlisted, all resolve on VM: hindsight, pdfid, pdf-parser, **pescan**, **densityscout**, packerid, page-brute (needs yara), analyzemft, indxparse, list_mft→folded, usnparser, sqlite-carver, mvt-ios, mvt-android, mac-apt, evtx_dump. `pe-scanner` dropped for the stronger `pescan`+`densityscout`. |
| F-7 preflight honesty | ⏭️ deferred | future Axis-F follow-up (XYE-48/49) |

New catalog files: `browser.yaml`, `filesystem.yaml`, `recovery.yaml`, `mobile.yaml`, `macos.yaml`. Validation: 49 targeted tests pass · `bash -n install.sh` OK · `validate_docs` OK · `git diff --check` clean. DENY_FLOOR untouched. Landed in PR #7.

## 7. Live `/mcp` proof + the 4th availability state (2026-06-18, gateway up, code NOT yet deployed)

Ran the new tools through the live gateway `run_command` (deployed gateway still runs old code; this tests execution under the agent RUN-3 sandbox):

| Tool | Kind | Result |
|---|---|---|
| `pescan` | native ELF (/usr/bin) | ✅ runs (exit 0) |
| `densityscout` | native ELF (/usr/local/bin) | ✅ runs (exit 0) |
| `recmd` | dotnet wrapper | ❌ `/usr/bin/dotnet: Permission denied` (126) |
| `EvtxECmd` (existing) | dotnet wrapper | ❌ `/usr/bin/dotnet: Permission denied` (126) — **pre-existing, not from this PR** |
| `hindsight.py` | python-venv wrapper | ❌ `Permission denied` on the script (126) |

**Finding — a 4th state beyond (allowlisted / cataloged / installed): executable-permitted by the RUN-3 Landlock allow-list.** The agent `run_command` sandbox installs a **curated read+execute (FS_RX) path allow-list** in `dfir_exec_launcher.py:328-356`: `/usr`, `/bin`, `/sbin`, `/lib`, `/lib64`, `/usr/local/bin`, `/opt/sift-mcps`, `/opt/zimmermantools`, `/opt/volatility3`, `/opt/hayabusa`, `/usr/share` (+ a dedicated `/etc/mime.types` grant *for vol's automagic*). A tool executes only if its binary **and the interpreter its shebang execs** both resolve under an allow-listed root:

- `vol` runs because `/opt/volatility3` is explicitly listed — its `#!/opt/volatility3/bin/python3` interpreter is permitted. (This is why `vol` works while other venv tools don't — it was whitelisted as a first-class tool.)
- `pescan` (/usr/bin), `densityscout` (/usr/local/bin) are native ELF under listed roots → run.
- `hindsight.py` and the other bucket-D venv wrappers fail: the script lives in `/usr/local/bin` (allowed) but its shebang interpreter is under `/opt/pyhindsight` (etc.), which is **not** on the allow-list → exec denied (EACCES).
- `recmd`/`EvtxECmd` (dotnet) fail at `/usr/bin/dotnet` even though `/usr` is listed — the .NET host additionally trips the write/seccomp floor on startup; this is **pre-existing** (existing EZ dotnet tools already cannot run under `run_command`; they run only in the ingest pipeline, outside the sandbox).

**Consequence / follow-up (separate, security-sensitive — NOT this PR):** to let the agent execute the python-venv bucket-D tools via `run_command`, add their `/opt/<tool>` roots to the `rx_paths` list in `dfir_exec_launcher.py` — exactly as `/opt/volatility3` already is (clear precedent). dotnet EZ tools additionally need the .NET runtime reconciled with the write/seccomp floor (harder; may stay ingest/operator-side). Both warrant security review since they widen the sandboxed agent's exec surface. Until then, interpreter-backed tools are cataloged/resolvable but operator/ingest-side only; native-ELF additions (`pescan`, `densityscout`) work today.
