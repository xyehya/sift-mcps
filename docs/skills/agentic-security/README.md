# agentic-security skill

An Agent Skills / Codex skill for assessing agentic AI and MCP server security, tailored for a DFIR platform with FastMCP or FastAPI, Supabase/Postgres, OpenSearch, Python workers, evidence parsing, and host command execution.

## What is inside

```text
agentic-security/
├── SKILL.md
├── agents/openai.yaml
├── assets/
│   ├── assessment-report-template.md
│   ├── aibom-template.json
│   ├── finding-template.md
│   ├── mcp-tool-contract-template.yaml
│   ├── policy_middleware_example.py
│   ├── risk-matrix.yaml
│   ├── supabase-rls-checklist.md
│   ├── threat-model-template.md
│   └── tool-policy-template.yaml
├── references/
│   ├── asi-risk-register.md
│   ├── assessment-methodology.md
│   ├── command-tool-hardening.md
│   ├── environment-profile.md
│   ├── mcp-fastapi-supabase-review.md
│   ├── safe-redteam-test-cases.md
│   ├── sources.md
│   └── supply-chain-governance.md
└── scripts/
    ├── agentic_security_scan.py
    ├── generate_report_skeleton.py
    └── validate_skill.py
```

## Install

### User-scoped Codex install

```bash
unzip agentic-security-skill.zip -d /tmp/agentic-security-skill
mkdir -p "$HOME/.agents/skills"
cp -a /tmp/agentic-security-skill/agentic-security "$HOME/.agents/skills/"
```

Or use the included installer after unzipping:

```bash
cd /tmp/agentic-security-skill/agentic-security
./install.sh --user
```

### Repo-scoped install

From the unzipped skill directory:

```bash
./install.sh --repo /path/to/your/repo
```

This copies the skill to:

```text
/path/to/your/repo/.agents/skills/agentic-security
```

Restart Codex if the skill does not appear immediately.

## Validate the skill package

```bash
python3 scripts/validate_skill.py .
```

## Run the static triage script manually

Repo-scoped install:

```bash
python3 .agents/skills/agentic-security/scripts/agentic_security_scan.py \
  --root . \
  --out .agentic-security
```

User-scoped install:

```bash
python3 "$HOME/.agents/skills/agentic-security/scripts/agentic_security_scan.py" \
  --root /path/to/your/repo \
  --out /path/to/your/repo/.agentic-security
```

Generate a report skeleton from scan JSON:

```bash
python3 .agents/skills/agentic-security/scripts/generate_report_skeleton.py \
  --scan-json .agentic-security/agentic-security-scan.json \
  --out .agentic-security/assessment-report.md
```

## Example Codex prompts

```text
$agentic-security assess this MCP server for ASI01-ASI10 risks. Focus on FastMCP tool descriptors, command execution tools, Supabase RLS, OpenSearch case isolation, evidence immutability, and worker job authorization. Run the bundled scanner first, then produce a prioritized remediation plan.
```

```text
$agentic-security review my host command MCP tool. Check for command injection, path traversal, dangerous defaults, missing approval gates, weak audit logging, and unsafe output handling. Patch only the policy middleware and tests needed for a safe first PR.
```

```text
$agentic-security threat-model the DFIR workflow from evidence upload to parsing, indexing, query, report generation, and MCP host command execution. Produce trust boundaries, abuse cases, ASI mapping, and tests.
```

## Notes

The scanner is intentionally conservative and does not prove exploitability. Treat it as a triage aid, then perform code review and targeted tests.
