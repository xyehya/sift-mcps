#!/usr/bin/env python3
"""Static triage helper for agentic AI, MCP, FastAPI, Supabase, OpenSearch, and DFIR worker repos.

This script is intentionally dependency-free and conservative. It does not prove exploitability;
it finds review leads that should be confirmed manually.
"""
from __future__ import annotations

import argparse
import dataclasses
import datetime as _dt
import fnmatch
import hashlib
import json
import os
import re
import sys
from pathlib import Path
from typing import Iterable, Sequence

SEVERITY_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
FAIL_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "none": 99}

DEFAULT_EXTENSIONS = {
    ".py", ".pyi", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs",
    ".sql", ".yaml", ".yml", ".json", ".toml", ".ini", ".cfg",
    ".env", ".example", ".sh", ".bash", ".zsh", ".dockerfile",
    "Dockerfile", "docker-compose.yml", "docker-compose.yaml",
}

IGNORE_DIR_NAMES = {
    ".git", ".hg", ".svn", "node_modules", ".next", "dist", "build", "out",
    "target", ".venv", "venv", "env", "__pycache__", ".pytest_cache",
    ".mypy_cache", ".ruff_cache", ".cache", ".tox", "coverage", ".agentic-security",
}

SECRET_PATTERNS = [
    re.compile(r"(?i)SUPABASE_SERVICE_ROLE_KEY\s*[=:]\s*['\"]?[^'\"\s]+"),
    re.compile(r"(?i)service[_-]?role[_-]?key\s*[=:]\s*['\"]?[^'\"\s]+"),
    re.compile(r"(?i)OPENAI_API_KEY\s*[=:]\s*['\"]?sk-[A-Za-z0-9_-]{20,}"),
    re.compile(r"(?i)JWT_SECRET\s*[=:]\s*['\"]?[^'\"\s]{16,}"),
    re.compile(r"(?i)AWS_SECRET_ACCESS_KEY\s*[=:]\s*['\"]?[A-Za-z0-9/+=]{30,}"),
]

@dataclasses.dataclass(frozen=True)
class Rule:
    rule_id: str
    title: str
    severity: str
    asi: str
    pattern: re.Pattern[str]
    recommendation: str
    file_globs: tuple[str, ...] = ("*",)

@dataclasses.dataclass
class Finding:
    rule_id: str
    title: str
    severity: str
    asi: str
    path: str
    line: int
    snippet: str
    recommendation: str

RULES: list[Rule] = [
    Rule(
        "ASI05-RCE-001",
        "subprocess shell=True may allow command injection",
        "Critical",
        "ASI05",
        re.compile(r"subprocess\.(run|Popen|call|check_call|check_output)\s*\([^\n]*shell\s*=\s*True"),
        "Replace shell=True with an executable allowlist and argument arrays. Validate paths and add timeout, cwd jail, env allowlist, and audit logging.",
        ("*.py",),
    ),
    Rule(
        "ASI05-RCE-002",
        "asyncio.create_subprocess_shell executes a shell command",
        "Critical",
        "ASI05",
        re.compile(r"asyncio\.create_subprocess_shell\s*\("),
        "Use asyncio.create_subprocess_exec with fixed executable and argument list. Reject model-generated shell strings.",
        ("*.py",),
    ),
    Rule(
        "ASI05-RCE-003",
        "os.system executes a shell command",
        "Critical",
        "ASI05",
        re.compile(r"\bos\.system\s*\("),
        "Replace os.system with subprocess.run([...], shell=False) through a policy-checked command wrapper.",
        ("*.py",),
    ),
    Rule(
        "ASI05-RCE-004",
        "dynamic eval or exec detected",
        "High",
        "ASI05",
        re.compile(r"(?<![A-Za-z0-9_\.])(eval|exec)\s*\("),
        "Remove dynamic code execution. Use explicit parsers, schemas, or a sandbox with review gates if code execution is truly required.",
        ("*.py", "*.js", "*.ts", "*.tsx"),
    ),
    Rule(
        "ASI05-RCE-005",
        "unsafe deserialization pattern detected",
        "High",
        "ASI05",
        re.compile(r"\b(pickle|dill)\.(load|loads)\s*\("),
        "Do not deserialize untrusted evidence or tool output with pickle/dill. Use JSON or signed, trusted formats only.",
        ("*.py",),
    ),
    Rule(
        "ASI05-RCE-006",
        "yaml.load may deserialize unsafe objects",
        "High",
        "ASI05",
        re.compile(r"\byaml\.load\s*\((?![^\n]*(SafeLoader|safe_load))"),
        "Use yaml.safe_load or yaml.load(..., Loader=yaml.SafeLoader) for untrusted configuration or evidence-derived YAML.",
        ("*.py",),
    ),
    Rule(
        "ASI02-TOOL-001",
        "dangerous shell pattern appears in code or config",
        "High",
        "ASI02, ASI05",
        re.compile(r"(?i)(rm\s+-rf|sudo\s+|curl\s+[^\n|;]*\|\s*(bash|sh)|wget\s+[^\n|;]*\|\s*(bash|sh)|chmod\s+777|bash\s+-c|sh\s+-c)"),
        "Require explicit human approval for high-impact host operations and replace dangerous shell patterns with named, typed operations.",
    ),
    Rule(
        "ASI03-ID-001",
        "Supabase service-role reference detected",
        "High",
        "ASI03",
        re.compile(r"(?i)(SUPABASE_SERVICE_ROLE_KEY|service[_-]?role)"),
        "Confirm this is backend-only and never exposed to UI, agents, tool outputs, logs, or browser bundles. Add explicit authorization checks before service-role actions.",
        ("*.py", "*.js", "*.jsx", "*.ts", "*.tsx", "*.env", "*.yml", "*.yaml", "*.json", "*.toml"),
    ),
    Rule(
        "ASI03-ID-002",
        "hard-coded secret-like value detected",
        "Critical",
        "ASI03, ASI04",
        re.compile(r"__SECRET_PATTERN_PLACEHOLDER__"),
        "Move secrets to a managed secret store or local-only environment file. Rotate any committed secret and add secret scanning to CI.",
    ),
    Rule(
        "ASI07-AUTH-001",
        "CORS wildcard detected",
        "Medium",
        "ASI07",
        re.compile(r"allow_origins\s*=\s*\[\s*['\"]\*['\"]\s*\]"),
        "Avoid wildcard CORS for authenticated routes. Use explicit origins per environment and avoid credentials with wildcard origins.",
        ("*.py",),
    ),
    Rule(
        "ASI07-AUTH-002",
        "TLS or certificate verification disabled",
        "High",
        "ASI07, ASI04",
        re.compile(r"(?i)(verify_certs\s*=\s*False|verify\s*=\s*False|ssl_verify\s*[:=]\s*false|verify_certs\s*[:=]\s*false)"),
        "Enable certificate verification outside local demo mode. Gate local-only insecure config with explicit environment checks.",
    ),
    Rule(
        "ASI03-ID-003",
        "default admin credential pattern detected",
        "High",
        "ASI03, ASI04",
        re.compile(r"(?i)(admin\s*[:=]\s*admin|OPENSEARCH_INITIAL_ADMIN_PASSWORD\s*[:=]\s*admin|password\s*[:=]\s*['\"]admin['\"])"),
        "Do not use default admin credentials outside local demos. Use per-environment secrets and rotate any exposed credentials.",
    ),
    Rule(
        "ASI02-TOOL-002",
        "MCP or tool descriptor may contain instruction-like language",
        "Medium",
        "ASI01, ASI02, ASI04",
        re.compile(r"(?i)(description\s*[:=].*(ignore previous|system prompt|developer message|always call|bypass|secret|token|must call))"),
        "Review tool descriptions for poisoning. Descriptions should state capability only, not behavior overrides, hidden instructions, or secrets.",
    ),
    Rule(
        "ASI06-RAG-001",
        "OpenSearch query appears to accept raw body or model/user query object",
        "Medium",
        "ASI06, ASI02",
        re.compile(r"\.(search|msearch)\s*\([^\n]*(body|query)\s*=\s*(request|payload|args|model|user|input|query)"),
        "Use a query builder that always injects case_id, size, timeout, and allowed query types. Do not pass raw DSL from model/user input.",
        ("*.py", "*.js", "*.ts", "*.tsx"),
    ),
    Rule(
        "ASI06-RAG-002",
        "OpenSearch result or RAG content may be appended without trust labeling",
        "Low",
        "ASI01, ASI06",
        re.compile(r"(?i)(rag|retriev|opensearch|search).*?(context|prompt|messages)"),
        "Ensure retrieved content is delimited, case-scoped, provenance-labeled, and treated as untrusted evidence content.",
        ("*.py", "*.js", "*.ts", "*.tsx"),
    ),
    Rule(
        "ASI05-PATH-001",
        "path traversal candidate detected",
        "Medium",
        "ASI05",
        re.compile(r"(?i)(open|Path|send_file|FileResponse)\s*\([^\n]*(filename|filepath|path|user_input|request|args)"),
        "Resolve paths and enforce an approved root. Reject traversal and symlink escape before opening files.",
        ("*.py",),
    ),
    Rule(
        "ASI02-SSRF-001",
        "server-side request built from variable URL",
        "Medium",
        "ASI02, ASI07",
        re.compile(r"\b(requests|httpx)\.(get|post|put|delete|request)\s*\([^\n]*(url|uri|endpoint|request|args|payload)"),
        "Add URL allowlists, block private/link-local metadata IPs, enforce timeouts, and avoid fetching model-provided URLs from privileged networks.",
        ("*.py",),
    ),
    Rule(
        "ASI09-LOG-001",
        "audit keyword not found near tool or command execution",
        "Info",
        "ASI09, ASI10",
        re.compile(r"(@.*tool|register_tool|subprocess\.|os\.system|create_subprocess)"),
        "For each tool/command path, confirm an append-only audit record captures actor, case_id, action, args, policy decision, approval, and result hash.",
        ("*.py",),
    ),
]

# Compile secret pattern into the placeholder rule dynamically to keep one reporting path.
SECRET_RULE_INDEX = next(i for i, r in enumerate(RULES) if r.rule_id == "ASI03-ID-002")
RULES[SECRET_RULE_INDEX] = dataclasses.replace(
    RULES[SECRET_RULE_INDEX],
    pattern=re.compile("|".join(f"(?:{p.pattern.replace('(?i)', '')})" for p in SECRET_PATTERNS), re.I),
)


def _is_probably_text(path: Path, max_file_size: int) -> bool:
    try:
        if path.stat().st_size > max_file_size:
            return False
        with path.open("rb") as fh:
            chunk = fh.read(2048)
        if b"\x00" in chunk:
            return False
        return True
    except OSError:
        return False


def _should_skip_path(path: Path) -> bool:
    parts = path.parts
    if ".agents" in parts and "skills" in parts and "agentic-security" in parts:
        return True
    return any(part in IGNORE_DIR_NAMES for part in parts)


def _matches_extension(path: Path, include_md: bool) -> bool:
    name = path.name
    suffix = path.suffix
    if include_md and suffix.lower() == ".md":
        return True
    if name in DEFAULT_EXTENSIONS or suffix.lower() in DEFAULT_EXTENSIONS:
        return True
    if name.startswith(".env"):
        return True
    return False


def _matches_glob(path: Path, globs: Sequence[str]) -> bool:
    as_posix = path.as_posix()
    return any(fnmatch.fnmatch(path.name, g) or fnmatch.fnmatch(as_posix, g) for g in globs)


def iter_files(root: Path, include_md: bool, max_file_size: int) -> Iterable[Path]:
    for dirpath, dirnames, filenames in os.walk(root):
        current = Path(dirpath)
        dirnames[:] = [d for d in dirnames if d not in IGNORE_DIR_NAMES and not _should_skip_path(current / d)]
        if _should_skip_path(current):
            continue
        for filename in filenames:
            path = current / filename
            if _should_skip_path(path):
                continue
            if not _matches_extension(path, include_md):
                continue
            if not _is_probably_text(path, max_file_size):
                continue
            yield path


def relpath(path: Path, root: Path) -> str:
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return path.as_posix()


def scan_text_file(path: Path, root: Path, rules: Sequence[Rule]) -> list[Finding]:
    findings: list[Finding] = []
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return findings
    lines = text.splitlines()
    for idx, line in enumerate(lines, start=1):
        for rule in rules:
            if not _matches_glob(path, rule.file_globs):
                continue
            if rule.pattern.search(line):
                # Reduce noise: the audit reminder is only useful if nearby lines do not contain audit/log/policy.
                if rule.rule_id == "ASI09-LOG-001":
                    window = "\n".join(lines[max(0, idx - 5): idx + 5]).lower()
                    if any(token in window for token in ("audit", "policy", "decision", "logger", "log.")):
                        continue
                findings.append(Finding(
                    rule_id=rule.rule_id,
                    title=rule.title,
                    severity=rule.severity,
                    asi=rule.asi,
                    path=relpath(path, root),
                    line=idx,
                    snippet=line.strip()[:300],
                    recommendation=rule.recommendation,
                ))
    return findings


def scan_fastapi_auth(path: Path, root: Path) -> list[Finding]:
    if path.suffix != ".py":
        return []
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return []
    out: list[Finding] = []
    route_re = re.compile(r"@\s*(app|router)\.(get|post|put|patch|delete)\s*\(")
    for i, line in enumerate(lines):
        if not route_re.search(line):
            continue
        window = "\n".join(lines[i:i + 12])
        if any(public in window.lower() for public in ("health", "metrics", "openapi", "docs")):
            continue
        if "Depends(" not in window and "Security(" not in window and "require_" not in window:
            out.append(Finding(
                rule_id="ASI03-ID-004",
                title="FastAPI route may lack explicit auth dependency",
                severity="Medium",
                asi="ASI03, ASI07",
                path=relpath(path, root),
                line=i + 1,
                snippet=line.strip()[:300],
                recommendation="Confirm this route has authentication and per-action authorization. Prefer explicit dependencies such as Depends(require_case_access).",
            ))
    return out


def scan_sql_rls(path: Path, root: Path) -> list[Finding]:
    if path.suffix.lower() != ".sql":
        return []
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    out: list[Finding] = []
    lower = text.lower()
    table_matches = list(re.finditer(r"create\s+table\s+(?:if\s+not\s+exists\s+)?([a-zA-Z_][\w.\"]*)", text, flags=re.I))
    for match in table_matches:
        table = match.group(1).strip('"')
        table_name = table.split(".")[-1].strip('"')
        # Only case/control-plane-looking tables get this warning; avoids noisy extension tables.
        nearby = text[match.start(): match.start() + 1500].lower()
        looks_case_scoped = any(tok in nearby for tok in ("case_id", "artifact_id", "evidence", "finding", "job", "ioc", "host_id"))
        if not looks_case_scoped:
            continue
        rls_re = re.compile(rf"alter\s+table\s+(?:only\s+)?(?:[\w\"]+\.)?\"?{re.escape(table_name)}\"?\s+enable\s+row\s+level\s+security", re.I)
        if not rls_re.search(text):
            line = text[:match.start()].count("\n") + 1
            out.append(Finding(
                rule_id="ASI03-RLS-001",
                title="case-scoped table may be missing RLS enablement",
                severity="High",
                asi="ASI03, ASI06",
                path=relpath(path, root),
                line=line,
                snippet=f"CREATE TABLE {table}",
                recommendation="Enable RLS and add SELECT/INSERT/UPDATE policies that enforce case membership and WITH CHECK on case_id.",
            ))
    for m in re.finditer(r"using\s*\(\s*true\s*\)|with\s+check\s*\(\s*true\s*\)", lower):
        line = text[:m.start()].count("\n") + 1
        out.append(Finding(
            rule_id="ASI03-RLS-002",
            title="broad RLS policy uses true",
            severity="High",
            asi="ASI03",
            path=relpath(path, root),
            line=line,
            snippet=text.splitlines()[line - 1].strip()[:300] if line - 1 < len(text.splitlines()) else "USING true",
            recommendation="Replace broad policies with case membership and role checks; add WITH CHECK for writes.",
        ))
    if "security definer" in lower and "set search_path" not in lower:
        line = lower.find("security definer")
        out.append(Finding(
            rule_id="ASI03-RLS-003",
            title="SECURITY DEFINER function may lack fixed search_path",
            severity="Medium",
            asi="ASI03, ASI04",
            path=relpath(path, root),
            line=text[:line].count("\n") + 1,
            snippet="SECURITY DEFINER",
            recommendation="Set a safe search_path and validate caller authority inside SECURITY DEFINER functions.",
        ))
    return out


def collect_inventory(path: Path, root: Path) -> dict[str, list[dict[str, object]]]:
    inventory: dict[str, list[dict[str, object]]] = {"mcp_tools": [], "fastapi_routes": [], "subprocess_calls": []}
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return inventory
    lines = text.splitlines()
    for i, line in enumerate(lines, start=1):
        stripped = line.strip()
        if re.search(r"@.*\btool\b|register_tool\s*\(|FastMCP\s*\(|Tool\s*\(", stripped):
            inventory["mcp_tools"].append({"path": relpath(path, root), "line": i, "text": stripped[:220]})
        if re.search(r"@\s*(app|router)\.(get|post|put|patch|delete)\s*\(", stripped):
            inventory["fastapi_routes"].append({"path": relpath(path, root), "line": i, "text": stripped[:220]})
        if re.search(r"subprocess\.|os\.system|create_subprocess", stripped):
            inventory["subprocess_calls"].append({"path": relpath(path, root), "line": i, "text": stripped[:220]})
    return inventory


def merge_inventory(target: dict[str, list[dict[str, object]]], incoming: dict[str, list[dict[str, object]]]) -> None:
    for key, values in incoming.items():
        target.setdefault(key, []).extend(values)


def sort_findings(findings: list[Finding]) -> list[Finding]:
    return sorted(findings, key=lambda f: (SEVERITY_ORDER.get(f.severity, 99), f.path, f.line, f.rule_id))


def summarize(findings: Sequence[Finding]) -> dict[str, int]:
    counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
    for finding in findings:
        counts[finding.severity] = counts.get(finding.severity, 0) + 1
    return counts


def render_markdown(payload: dict[str, object]) -> str:
    findings = [Finding(**f) for f in payload["findings"]]  # type: ignore[index]
    counts = payload["summary"]  # type: ignore[index]
    lines: list[str] = []
    lines.append("# Agentic Security Static Triage")
    lines.append("")
    lines.append(f"- **Generated:** {payload['generated_at']}")
    lines.append(f"- **Root:** `{payload['root']}`")
    lines.append(f"- **Files scanned:** {payload['files_scanned']}")
    lines.append(f"- **Findings:** Critical {counts['Critical']}, High {counts['High']}, Medium {counts['Medium']}, Low {counts['Low']}, Info {counts['Info']}")
    lines.append("")
    lines.append("> This is static triage only. Confirm every important issue manually and map it to the architecture before reporting.")
    lines.append("")

    inv = payload.get("inventory", {})  # type: ignore[assignment]
    if isinstance(inv, dict):
        lines.append("## Inventory leads")
        for key in ("mcp_tools", "fastapi_routes", "subprocess_calls"):
            values = inv.get(key, []) if isinstance(inv, dict) else []
            lines.append(f"- **{key}:** {len(values)}")
        lines.append("")

    lines.append("## Findings")
    if not findings:
        lines.append("")
        lines.append("No findings matched the built-in rules.")
    for n, f in enumerate(findings, start=1):
        lines.append("")
        lines.append(f"### {n}. {f.title}")
        lines.append("")
        lines.append(f"- **Rule:** `{f.rule_id}`")
        lines.append(f"- **Severity:** {f.severity}")
        lines.append(f"- **ASI:** {f.asi}")
        lines.append(f"- **Location:** `{f.path}:{f.line}`")
        lines.append(f"- **Snippet:** `{f.snippet.replace('`', 'ˋ')}`")
        lines.append(f"- **Recommendation:** {f.recommendation}")
    lines.append("")
    return "\n".join(lines)


def render_sarif(payload: dict[str, object]) -> dict[str, object]:
    findings = [Finding(**f) for f in payload["findings"]]  # type: ignore[index]
    rules: dict[str, dict[str, object]] = {}
    results = []
    for f in findings:
        rules.setdefault(f.rule_id, {
            "id": f.rule_id,
            "name": f.title,
            "shortDescription": {"text": f.title},
            "help": {"text": f.recommendation},
            "properties": {"severity": f.severity, "asi": f.asi},
        })
        level = {"Critical": "error", "High": "error", "Medium": "warning", "Low": "note", "Info": "note"}.get(f.severity, "warning")
        results.append({
            "ruleId": f.rule_id,
            "level": level,
            "message": {"text": f"{f.title} ({f.asi}): {f.recommendation}"},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": f.path},
                    "region": {"startLine": f.line},
                }
            }],
        })
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "agentic_security_scan", "rules": list(rules.values())}},
            "results": results,
        }],
    }


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Static triage for agentic AI and MCP security risks.")
    parser.add_argument("--root", default=".", help="Target repository root to scan.")
    parser.add_argument("--out", default=".agentic-security", help="Output directory for JSON, Markdown, and SARIF.")
    parser.add_argument("--include-md", action="store_true", help="Also scan Markdown files. This can be noisy for security docs.")
    parser.add_argument("--max-file-size", type=int, default=2_000_000, help="Skip files larger than this many bytes.")
    parser.add_argument("--fail-on", choices=list(FAIL_ORDER), default="none", help="Exit non-zero if findings at or above this severity exist.")
    args = parser.parse_args(argv)

    root = Path(args.root).expanduser().resolve()
    out_dir = Path(args.out).expanduser().resolve()
    if not root.exists():
        print(f"Root does not exist: {root}", file=sys.stderr)
        return 2
    out_dir.mkdir(parents=True, exist_ok=True)

    all_findings: list[Finding] = []
    inventory: dict[str, list[dict[str, object]]] = {"mcp_tools": [], "fastapi_routes": [], "subprocess_calls": []}
    files_scanned = 0
    for path in iter_files(root, include_md=args.include_md, max_file_size=args.max_file_size):
        files_scanned += 1
        all_findings.extend(scan_text_file(path, root, RULES))
        all_findings.extend(scan_fastapi_auth(path, root))
        all_findings.extend(scan_sql_rls(path, root))
        merge_inventory(inventory, collect_inventory(path, root))

    all_findings = sort_findings(all_findings)
    payload = {
        "generated_at": _dt.datetime.now(_dt.timezone.utc).isoformat(),
        "root": root.as_posix(),
        "root_sha_hint": hashlib.sha256(root.as_posix().encode()).hexdigest()[:12],
        "files_scanned": files_scanned,
        "summary": summarize(all_findings),
        "findings": [dataclasses.asdict(f) for f in all_findings],
        "inventory": inventory,
    }

    json_path = out_dir / "agentic-security-scan.json"
    md_path = out_dir / "agentic-security-scan.md"
    sarif_path = out_dir / "agentic-security-scan.sarif"
    json_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    md_path.write_text(render_markdown(payload), encoding="utf-8")
    sarif_path.write_text(json.dumps(render_sarif(payload), indent=2), encoding="utf-8")

    counts = payload["summary"]
    print(f"Scanned {files_scanned} files under {root}")
    print(f"Findings: Critical {counts['Critical']}, High {counts['High']}, Medium {counts['Medium']}, Low {counts['Low']}, Info {counts['Info']}")
    print(f"Wrote: {json_path}")
    print(f"Wrote: {md_path}")
    print(f"Wrote: {sarif_path}")

    threshold = FAIL_ORDER[args.fail_on]
    if threshold < 99:
        for f in all_findings:
            if SEVERITY_ORDER.get(f.severity, 99) <= threshold:
                return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
