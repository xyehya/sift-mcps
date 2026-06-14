#!/usr/bin/env python3
"""Generate an assessment report skeleton from agentic_security_scan.py JSON output."""
from __future__ import annotations

import argparse
import datetime as _dt
import json
from pathlib import Path
from typing import Any


def load_scan(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def severity_priority(sev: str) -> str:
    return {
        "Critical": "P0",
        "High": "P1",
        "Medium": "P2",
        "Low": "P3",
        "Info": "P3",
    }.get(sev, "P3")


def render(scan: dict[str, Any]) -> str:
    findings = scan.get("findings", [])
    counts = scan.get("summary", {})
    generated = _dt.datetime.now(_dt.timezone.utc).date().isoformat()
    lines: list[str] = []
    lines.append("# Agentic Security Assessment Report")
    lines.append("")
    lines.append(f"- **Target:** `{scan.get('root', '')}`")
    lines.append(f"- **Date:** {generated}")
    lines.append("- **Assessor:** Codex with agentic-security skill")
    lines.append("- **Scope:** MCP server, agent tools, FastAPI gateway, Supabase/Postgres, OpenSearch, worker runtime, evidence handling")
    lines.append("- **Assumptions:** Static scan findings require manual confirmation")
    lines.append("")
    lines.append("## 1. Executive summary")
    lines.append("")
    lines.append(f"Static triage found Critical {counts.get('Critical', 0)}, High {counts.get('High', 0)}, Medium {counts.get('Medium', 0)}, Low {counts.get('Low', 0)}, and Info {counts.get('Info', 0)} findings. Confirm exploitability and prioritize command execution, credentials, auth/RLS, case isolation, evidence integrity, and privileged tool policy first.")
    lines.append("")
    lines.append("## 2. Architecture and trust boundaries")
    lines.append("")
    lines.append("| Boundary | Producer | Consumer | Data | Identity | Main risks |")
    lines.append("|---|---|---|---|---|---|")
    lines.append("| Agent client to MCP server | Agent/Codex | FastMCP/FastAPI | Tool calls and context | User/agent | ASI01, ASI02, ASI03 |")
    lines.append("| MCP server to worker | Gateway | Python worker | Jobs and artifacts | Service/worker | ASI03, ASI07, ASI08 |")
    lines.append("| Worker to host OS | Worker | Linux/SIFT tools | Commands and evidence paths | OS user | ASI02, ASI05 |")
    lines.append("| App to Supabase | UI/API/worker | Postgres/Auth/Storage | Case state | User/service | ASI03, ASI06 |")
    lines.append("| App to OpenSearch | API/worker | Search index | Evidence-derived docs | Service | ASI06 |")
    lines.append("")
    lines.append("## 3. Findings overview")
    lines.append("")
    lines.append("| ID | Severity | ASI | Component | Finding | Priority |")
    lines.append("|---|---|---|---|---|---|")
    for i, f in enumerate(findings, start=1):
        component = "TBD"
        path = str(f.get("path", ""))
        if "sql" in path or "migration" in path:
            component = "Supabase/Postgres"
        elif "opensearch" in path.lower() or "search" in path.lower():
            component = "OpenSearch/RAG"
        elif "worker" in path.lower() or "subprocess" in str(f.get("snippet", "")):
            component = "Worker/Command"
        elif "api" in path.lower() or "route" in path.lower():
            component = "FastAPI"
        lines.append(f"| F-{i:03d} | {f.get('severity')} | {f.get('asi')} | {component} | {str(f.get('title', '')).replace('|', '/')} | {severity_priority(str(f.get('severity')))} |")
    if not findings:
        lines.append("| - | - | - | - | No scanner findings | - |")
    lines.append("")
    lines.append("## 4. Detailed findings")
    for i, f in enumerate(findings, start=1):
        lines.append("")
        lines.append(f"### F-{i:03d}: {f.get('title')}")
        lines.append("")
        lines.append(f"- **Severity:** {f.get('severity')}")
        lines.append(f"- **ASI mapping:** {f.get('asi')}")
        lines.append(f"- **Component:** TBD")
        lines.append(f"- **Evidence:** `{f.get('path')}:{f.get('line')}` — `{str(f.get('snippet', '')).replace('`', 'ˋ')}`")
        lines.append("")
        lines.append("#### Why it matters")
        lines.append("")
        lines.append("Explain realistic impact in this DFIR/MCP architecture.")
        lines.append("")
        lines.append("#### Recommended fix")
        lines.append("")
        lines.append(str(f.get("recommendation", "")))
        lines.append("")
        lines.append("#### Verification")
        lines.append("")
        lines.append("Add a regression test that fails before the fix and passes after.")
    lines.append("")
    lines.append("## 5. Remediation roadmap")
    lines.append("")
    lines.append("### P0")
    lines.append("- Fix confirmed Critical items, especially RCE, credential exposure, cross-case leakage, and evidence mutation.")
    lines.append("")
    lines.append("### P1")
    lines.append("- Fix High items before multi-user or production-like use.")
    lines.append("")
    lines.append("### P2/P3")
    lines.append("- Address hardening, audit, documentation, and consistency items.")
    lines.append("")
    lines.append("## 6. Tests to add")
    lines.append("")
    lines.append("| Test | ASI | Expected result | Location |")
    lines.append("|---|---|---|---|")
    lines.append("| Prompt injection in evidence text | ASI01 | Treated as content, not instruction | tests/security/ |")
    lines.append("| Filename shell metacharacters | ASI05 | Rejected or treated literally | tests/security/ |")
    lines.append("| Cross-case query | ASI03/ASI06 | No data returned, audit event emitted | tests/security/ |")
    lines.append("| High-risk tool call without approval | ASI02/ASI09 | Blocked with policy decision | tests/security/ |")
    lines.append("")
    lines.append("## 7. Open questions")
    lines.append("")
    lines.append("- Which routes/tools are intentionally public or local-only?")
    lines.append("- Which deployment modes are demo-only versus production-like?")
    lines.append("- Which agent identities and scopes are planned for each case role?")
    lines.append("")
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate an assessment report skeleton from scan JSON.")
    parser.add_argument("--scan-json", required=True, help="Path to agentic-security-scan.json")
    parser.add_argument("--out", required=True, help="Output markdown report path")
    args = parser.parse_args()
    scan_path = Path(args.scan_json).expanduser().resolve()
    out_path = Path(args.out).expanduser().resolve()
    scan = load_scan(scan_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(render(scan), encoding="utf-8")
    print(f"Wrote {out_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
