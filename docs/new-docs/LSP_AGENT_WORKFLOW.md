# LSP Agent Workflow

> Covers: Pyright, Ruff, TypeScript language server, Codex, Claude Code
> Class: live-reference
> Last validated: 7fd90a7 (2026-06-26)

Status: repo baseline for using Language Server Protocol tooling with human
editors and coding agents.

## 1. What LSP Solves

Language Server Protocol gives tools a structured view of code that grep does
not have:

- Go to definition, find references, symbol rename, hover docs, and import
  resolution.
- Fast diagnostics for the file being edited, before a full test run.
- Safer cross-file edits because the agent can ask "who uses this symbol?" and
  verify names against the language server.
- Fewer path/import mistakes in this repo's `packages/*/src` workspace layout.

It does not replace tests, runtime smoke checks, security review, or
codebase-memory. In this repo, use codebase-memory for structural discovery and
call-chain questions, then use LSP diagnostics to tighten the files you are
editing.

## 2. Repo Language Servers

Python:

- Pyright: type-aware Python language server and type checker.
- Ruff: lint language server and fast import/style diagnostics.
- Reproducible commands:

```bash
./scripts/lsp/pyright-langserver.sh
./scripts/lsp/ruff-server.sh
uv run --extra dev pyright
uv run --extra dev pyright packages/sift-gateway/src/sift_gateway/policy_middleware.py
uv run --extra dev ruff check <paths>
```

Frontend:

- TypeScript language server for JavaScript/JSX symbol navigation, React hover
  info, imports, and `@/` alias awareness through `jsconfig.json`.
- ESLint remains the lint validator.
- Reproducible commands:

```bash
./scripts/lsp/typescript-language-server.sh
npm --prefix packages/case-dashboard/frontend run lsp
npm --prefix packages/case-dashboard/frontend run lint
```

## 3. Current Pyright Baseline

`pyrightconfig.json` is intentionally scoped to the currently type-clean gateway
baseline instead of every package. Broader package probes currently surface
legacy type debt in large modules such as portal routes, opensearch server code,
and some core helpers.

Agent rule:

1. Run `uv run --extra dev pyright` before closing Python work.
2. Also run targeted Pyright on every non-baseline Python file you touch.
3. Do not expand `pyrightconfig.json` to all `packages/**` until the target
   package is made clean or the expected diagnostics are explicitly ratcheted.

The intended ratchet path is package by package:

1. `sift-gateway`
2. `sift-core`
3. `case-dashboard` backend
4. `opensearch-mcp`
5. smaller add-ons and knowledge packages

## 4. Claude Code Usage

Claude Code can use LSP in normal interactive sessions. Do not start with
`--bare` when you want code intelligence; local `claude --help` says bare mode
skips LSP, plugins, MCP sync, and auto-discovery.

Start from the correct working tree:

```bash
cd /home/yk/AI/SIFTHACK/sift-mcps
claude
```

For portal v3 UI work, start from the portal worktree instead:

```bash
cd /home/yk/AI/SIFTHACK/sift-mcps/.claude/worktrees/portal-v3-p0-foundation
claude
```

Useful session instruction:

```text
Use codebase-memory for structural discovery. Use LSP/Pyright/Ruff diagnostics
for files you edit. Run targeted Pyright on any non-baseline Python file touched
and frontend lint for portal changes.
```

## 5. Codex Usage

Codex CLI exposes MCP management, but this local CLI does not expose a direct
"attach to this LSP server" command. Use the repo's language-server setup in two
ways:

1. Let Codex use the existing `codebase-memory` MCP for structural discovery.
   The indexer already performs type-aware call and usage resolution.
2. Ask Codex to run the same validators that back the language servers:

```bash
uv run --extra dev pyright
uv run --extra dev pyright <python-file-you-touched>
uv run --extra dev ruff check <paths>
npm --prefix packages/case-dashboard/frontend run lint
```

If a future Codex session uses an LSP-to-MCP bridge, point that bridge at the
repo wrapper commands instead of global binaries:

```bash
./scripts/lsp/pyright-langserver.sh
./scripts/lsp/ruff-server.sh
./scripts/lsp/typescript-language-server.sh
```

## 6. What To Ask Agents

Good prompt for implementation work:

```text
Before editing, use codebase-memory for symbol discovery and then use the repo
LSP/validator commands for the files you change. Do not rely only on grep for
Python or frontend symbol relationships. Keep Pyright's global baseline clean;
for non-baseline files, run targeted Pyright and report existing diagnostics
separately from new ones.
```

Good prompt for reviews:

```text
Review with LSP discipline: check renamed symbols, imports, references, and
changed-file diagnostics. Findings should distinguish confirmed defects from
pre-existing type debt outside the changed surface.
```

## 7. Practical Boundaries

- LSP catches many import, signature, optional-value, and rename mistakes early.
- LSP will not prove policy correctness, runtime permissions, database state, or
  live VM behavior.
- Keep codebase-memory first for call graphs and architecture questions.
- Keep tests and live proof as the final authority for behavior.
