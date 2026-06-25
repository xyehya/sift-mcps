# SIFT Examiner Portal — Design Brief for Claude Design

> Paste/upload this into claude.ai/design as the brief. We are handing you the
> **concept, the domain theme, and the technical requirements** — and explicitly
> handing **the visual identity, palette, typography, and design language to you**.
> No colors are prescribed. You know better. Make it exceptional.

---

## 1. The product — in one line

A human-in-the-loop **Command & Control portal** that lets a forensic examiner
**drive, monitor, and authorize an autonomous AI agent (Claude Code)** which is
running a full **digital-forensics & incident-response (DFIR) investigation
pipeline** via MCP tools on a forensic workstation.

It is **mission control for supervising an AI investigator** — not a passive
case dashboard. The agent does the heavy lifting (parses disk/memory/log
evidence, runs forensic tooling, proposes findings, timelines, IOCs); the human
**supervises**: reviews proposals, approves/rejects, **authorizes risky or
irreversible actions**, and **commits** results to an immutable, evidence-grade
record.

## 2. Who uses it & the stakes

- **User:** a forensic examiner / IR operator. Single operator, expert, focused.
- **Context:** high-stakes, evidence-grade, legally-defensible work. Every action
  is audited; evidence integrity and chain-of-custody are sacred.
- **Feeling we want:** a trustworthy, precise, calm **operator console** — SOC /
  mission-control energy. Authoritative, legible under pressure, not noisy.
- **Desktop-first** (1440+), must also work at 1024 / 768 / 375.

## 3. What it must do (functional surface — keep all of it)

**Destinations (11):** Overview (mission dashboard / hero), Findings, Timeline,
Evidence, Hosts, Accounts, IOCs, TODOs, Backends (MCP tool/server health),
Reports, Settings.

**Core operator loops:**
- **Supervise the agent:** see what the agent is doing *right now* (live status:
  working / awaiting-authorization / idle), its proposals, and a feed of its
  actions. **Authorize gated actions** the agent cannot self-approve (e.g. run a
  risky command, seal/unseal evidence) — a clear approve/deny moment.
- **Findings review → commit:** examiner reviews agent-proposed findings (each has
  Observation/Fact, Interpretation/Analysis, Confidence & Justification),
  approves / rejects / edits, **stages** them, then **commits** to the record
  (review the delta, confirm). Keyboard-driven (e.g. j/k navigate, a approve,
  r reject).
- **Evidence chain-of-custody:** registered / sealed / write-protected state,
  integrity hashes, manifest; unseal requires re-auth. Integrity is front-and-centre.
- **Investigative entities** the agent populates: Timeline, IOCs, Hosts, Accounts
  — data-dense, filterable, sortable.
- **Backends:** health/status of the MCP servers & tools the agent drives.
- **Reports:** generate + view.

**States that must be designed (not afterthoughts):** agent working /
awaiting-authorization / idle; case sealed / write-protected; finding
pending / staged / approved / rejected; evidence sealed / registered;
empty / loading (skeletons) / no-case / error.

**Roles:** examiner (can act) vs read-only (view + reason shown for hidden actions).

## 4. DFIR theme & domain vocabulary

- **Evidence integrity:** SEALED, WRITE-PROTECTED, chain-of-custody, manifest,
  cryptographic hashes, immutability, "commit to record".
- **Severity:** high / medium / low / speculative. **Status:** approved /
  pending / staged / rejected. **Custody grade:** full / partial / none.
- **Forensic entities:** MITRE ATT&CK techniques, IOCs, hosts, accounts, EVTX
  events, registry keys, timestamps, IPs, file paths — these are precise,
  copyable, **monospace** data.
- **Tone:** serious, exact, evidence-grade, trustworthy. Convey *authority and
  custody*, and the live presence of an autonomous agent under human command.

## 5. Technical requirements (so your designs map 1:1 onto shippable code)

- **Stack:** React 19 + Vite + **Tailwind 4** + **shadcn/ui** (vendored) +
  framer-motion + recharts.
- **Token-driven:** a single CSS design-token source; **dark + light** themes,
  system-aware and persisted. (Give us both themes, as a paired system.)
- **Security-constrained styling:** self-hosted fonts (no external CDN), tight
  CSP, **no inline styles** — everything expressible as tokens + utility classes.
- **Accessibility:** WCAG **AA in both themes**; visible focus rings; honor
  `prefers-reduced-motion`; full keyboard nav; `⌘K` command palette.
- **Typography:** a clean UI sans + a **monospace for all forensic data**
  (hashes, IDs, timestamps, paths, IPs). Base ≈15px, real type scale, tabular
  figures for data columns.
- **Data viz:** trend (finding velocity over time), distribution (severity), each
  with legend / tooltip / empty / loading / AA contrast / table alternative.
- **Layout:** persistent sidebar nav ≥1024 (collapsible below), header strip,
  status bar. Data-dense tables. Motion: purposeful, transform/opacity only,
  reduced-motion safe.

## 6. What we are asking YOU (Claude Design) to own

- **Visual identity + full palette (dark & light)** — we are **not** prescribing
  colors. Make it feel like a trustworthy forensic **mission-control console for
  commanding an autonomous AI investigator**.
- Typography pairing, spacing scale, elevation, shadow, radius, motion language.
- The **Overview "mission dashboard"** — the operator's at-a-glance command view
  of *the agent* + *the case* (its status, what needs authorization, case health,
  finding/severity/evidence summary, recent agent activity). This is the hero;
  make it sing.
- The component look across all destinations, as a coherent system.

## 7. Anti-goals (what to avoid)

- Not the tired **cyan-on-navy "hacker terminal"** cliché.
- Not generic **fintech green-success** dashboards.
- Not playful / consumer / marketing energy.
- No emoji as icons (use a single SVG icon family). No meaning conveyed by color
  alone. Nothing that undermines the feeling of evidence-grade trust.

---

*Deliverable back to engineering: the chosen design tokens (both themes) + the
key screens (Overview + Findings as canonical patterns). We re-lock those tokens
into the token source and the rest of the system inherits them.*
