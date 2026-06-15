# B-MVP-042 — Memory-image hostname auto-derivation (implementation spec)

**Status:** approach PROVEN on the live VM (2026-06-15, read-only). Not yet implemented.
**Owner backlog:** B-MVP-042 (`docs/migration/Session-Notes.md`).

## Problem

`opensearch_ingest(format="memory", …)` hard-requires an explicit `hostname=` and
returns `"hostname is required for format='memory'."` (`server.py:2249` branch)
before any Volatility runs. Unlike the disk/evtx path — where each record
self-identifies via its `Computer` field — a vol process/network listing has no
per-record host, so the hostname is needed up front to (a) build the index name
(`parse_memory.py:_build_idx`, ~line 430) and (b) tag every record
(`record["host.name"]`, ~line 321). The existing host-discovery orchestrator
(`host_discovery.py::discover_hosts`) is wired only into the `format=auto`
directory path and has **no memory-image source**, so nothing derives the
hostname from a raw image today. This was the real cause of the B-MVP-037
"0 docs" symptom (the guard fired in <1s; vol never ran).

The memory image *does* carry the hostname (SYSTEM-hive `ComputerName` and every
process's `COMPUTERNAME` env var). `hostname.py` already implements the canonical
ControlSet001/002 → ActiveComputerName → ComputerName logic for *mounted volumes*
(regipy); this spec is the memory (vol3) equivalent.

## Proven probe results (live VM, `Rocba-Memory.raw`, 19 GB)

- Binary `/usr/local/bin/vol` (Volatility 3 Framework 2.27.0); symbols
  `-s /var/cache/sift/volatility-symbols` (warm Win10 ISF cache, no download).
- Run as `sift-service`, `cwd=/opt/sift-mcps`, `HOME=/var/lib/sift` (same env as the
  proven `windows.pslist` ingest run). EXIT=0, ~1.6–2.0 s each.
- **All three approaches returned `SRL-FORGE`** — identical to the `hostname=SRL-FORGE`
  used for the successful ingest. Auto-derive reproduces the same index name.

### Approach A — registry ComputerName (PRIMARY / canonical)

```
vol -s /var/cache/sift/volatility-symbols -f <image> -q -r json \
    windows.registry.printkey --key "ControlSet001\Control\ComputerName\ActiveComputerName"
# fallback key: "ControlSet001\Control\ComputerName\ComputerName"
# fallback control set: ControlSet002 if 001 empty/absent
```

`-r json` returns a flat array of row objects with keys
`["Data","Hive Offset","Key","Last Write Time","Name","Type","Volatile","__children"]`.
The hostname row (verbatim):

```json
{"Data": "\"SRL-FORGE\"", "Key": "\\REGISTRY\\MACHINE\\SYSTEM\\ControlSet001\\Control\\ComputerName\\ComputerName",
 "Name": "ComputerName", "Type": "REG_SZ", "Last Write Time": "2020-11-02T01:12:22+00:00", "Volatile": false}
```

Parse: `json.loads` → pick the row where `Name == "ComputerName"` **and**
`Type == "REG_SZ"` **and** `Key` contains `\REGISTRY\MACHINE\SYSTEM\` and ends with
`\Control\ComputerName\<subkey>` → take `Data` → **strip the surrounding literal
double-quotes** (REG_SZ renders as `"SRL-FORGE"` inside the JSON string).

### Approach B — env var (CROSS-CHECK / secondary, simpler to parse)

```
vol -s /var/cache/sift/volatility-symbols -f <image> -q -r json windows.envars
```

Flat array; row keys `["Block","PID","Process","Value","Variable","__children"]`.
Filter `Variable.upper() == "COMPUTERNAME"`; take the majority/first `Value`.
On the test image: **181 rows, all `Value == "SRL-FORGE"`** (unanimous). The
`Value` here is the **raw** string — no quote-stripping needed.

## Recommended implementation

Add a preflight in the memory path (in `opensearch_ingest`'s `format=="memory"`
branch in `server.py`, or inside `idx_ingest_memory` in `parse_memory.py`):

1. If `hostname` is supplied → use it (operator override, unchanged).
2. Else derive it from the image:
   a. Approach A: `windows.registry.printkey` on `ActiveComputerName`, then
      `ComputerName`; ControlSet001 then ControlSet002. Strip REG_SZ quotes.
   b. If A yields nothing: Approach B (`windows.envars` COMPUTERNAME majority).
3. Canonicalize the derived raw via `host_dictionary.resolve()` (the memory path
   already calls this at `parse_memory.py:324`), so it folds into the case host
   dictionary like any other source.
4. Only if both A and B fail → return the current
   `"hostname is required for format='memory'"` error (now a true last resort).
5. Surface the derived value in the result (e.g. `"hostname_source": "registry"|"envars"|"operator"`)
   so the agent sees what was used, and keep `hostname=` as an explicit override.

This mirrors `hostname.py`'s mounted-volume precedence (ActiveComputerName →
ComputerName, ControlSet001 → 002) but reads the in-memory SYSTEM hive via vol3.

## Gotchas

1. **REG_SZ quote-wrapping:** registry `Data` is `"\"SRL-FORGE\""` — strip surrounding `"`.
   Env-var `Value` is raw (no stripping).
2. **printkey returns many rows:** the `--key` query matches the path across every
   hive in memory (~45 rows: SYSTEM/SOFTWARE/per-user NTUSER/app `.dat`). Only the
   `\REGISTRY\MACHINE\SYSTEM\` row with `Name=="ComputerName"`/`Type=="REG_SZ"`
   carries the value; the rest are empty key-nodes (`Data == "-"`). Filter accordingly.
3. **ControlSet fallback:** prefer `ActiveComputerName`, fall back to `ComputerName`;
   `ControlSet001` → `ControlSet002`. (CS001 was populated on the test image.)
4. **Cost:** ~1.6–2.0 s with a warm symbol cache — negligible to prepend to a memory
   ingest. A first-ever run on an uncached Win build pays the one-time ISF generation.
5. **Use `-r json`, never the ASCII grid:** the grid's `Key` column contains
   backslashes/spaces and dozens of irrelevant rows; JSON gives stable typed objects.

## Related

Also seen: cosmetic double `case-case-` prefix on the vol index name (minor; same
B-MVP-042). Discovery orchestrator gap noted in B-MVP-041 context.
