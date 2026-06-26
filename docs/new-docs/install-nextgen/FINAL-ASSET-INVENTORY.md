# FINAL — Download Asset Inventory (Signed Off)

**Track B deliverable · Status: ACCEPTED · Date: 2026-06-19**

This is the signoff cover for the team's download-asset inventory. The accepted
artifact is **[`03-DOWNLOAD-ASSET-INVENTORY.md`](03-DOWNLOAD-ASSET-INVENTORY.md)**
(DRAFT v2 + 2 post-clearance cosmetic fixes = effective **v2.1**). The full
review trail is in `04-INVENTORY-REVIEW-r1.md` (CHANGES REQUIRED) and
`04-INVENTORY-REVIEW-r2.md` (CLEARED).

## Provenance / process

| Step | Agent | Result |
|------|-------|--------|
| Authoring v1 | Inventory (general-purpose) | 24 rows, 9 gaps |
| Review r1 | Auditor (general-purpose, independent) | **CHANGES REQUIRED** — 3 major, 6 minor |
| Authoring v2 | Inventory | 28 rows, G1–G11; all 9 items addressed; headline conclusion corrected |
| Review r2 | Auditor | **CLEARED** — 0 blocker, 0 major, 2 minor (optional) |
| Post-clearance polish | Lead | Applied both nits (n1 repo count, n2 cap attribution) |

The Auditor re-verified all three r1 majors and the new rows against source code
(not the changelog) before clearing. Independent reviewer ≠ author, which is what
surfaced the single most important finding (M1, below).

## Auditor signoff (verbatim, r2 §5)

> **CLEARED.** The inventory is complete and accurate to the source as of this
> revision. All round-1 majors and minors are resolved and independently
> re-verified; the 24 original rows plus the 4 added rows (#15b, #25a, #25b, #26)
> are anchored to correct `file:line` evidence; the trust tiers, endpoint
> traceability, offline posture, and gap set (G1-resolved, G2–G11) faithfully
> reflect the code.

## Lead acceptance

Accepted as the canonical asset inventory for the install-modernization effort.
The two r2 nits were cosmetic and are now fixed in `03`:
- **n1** — RAG git-feed count corrected to **20 git repos + 2 JSON feeds = 22 origins** (was inconsistently "~17"/"17+"/"<22").
- **n2** — clarified the 60 MB cap applies to the API/JSON fetch path only; `git clone` is **uncapped** (`sources.py:642`).

## Headline conclusion (carried from v2)

The largest unpinned supply-chain surface is **NOT** the private GitHub release
channel — it is the **forensic-rag online-source subsystem**: ~20 third-party
`git clone HEAD` threat-intel feeds (SigmaHQ, the full MITRE set, LOLBAS/GTFOBins/
HijackLibs/LOLDrivers, atomic/stratus red team, KAPE, Velociraptor, chainsaw,
hayabusa-rules) + 2 live gov JSON feeds (d3fend.mitre.org, cisa.gov KEV), pulled
by `rag-mcp refresh` (`skip_online` defaults False) with host-allowlist guards but
**no content/commit pinning**. It is NOT run by `install.sh` (`download_index.py:379`
passes `skip_online=True`) — it is a maintenance/runtime surface. This matters
because a forensic tool's detections derive from these feeds.

## Residual open gaps (carry-forward — feed to Linear XYE-48 / F2–F4)

These are documented-but-unresolved; they are remediation work, not inventory defects:

- **G1-residual** — no provenance link from the committed Vite bundle to a reproducible build.
- **G2** — windows-triage downloader has no offline guard (inconsistent with `install.sh`).
- **G3** — `latest`-tag resolution for first-party data assets (RAG bundle + triage DBs).
- **G4** — exact sizes/digests of triage baseline DBs unknown.
- **G5** — Supabase stack image set not enumerated in-repo.
- **G6** — Volatility ISF symbol endpoint not pinned/asserted.
- **G7** — OpenCTI connectors pull external threat feeds at runtime.
- **G8** — `uv` arch-fallback path is unhashed (non-x86_64 pipes an unverified script).
- **G9** — minio image `:latest` in the OpenCTI stack.
- **G10** — RAG online-source subsystem has no content/commit pinning (the headline surface).
- **G11** — RAG alternate embedding models unpinned.

## Feeds directly into

- **Linear XYE-48** (F0: network fetch inventory) — this IS that inventory; ready to attach.
- **Track A** (install modernization) — the registry-publishing blueprint must preserve/upgrade the pinning posture these gaps expose (esp. G8, G10).
