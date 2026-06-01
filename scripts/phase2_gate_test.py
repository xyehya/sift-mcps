#!/usr/bin/env python3
"""Phase 2 gate e2e test — runs on the VM against the live gateway.

Setup (run once, idempotent):
  - Creates /cases/phase2-gate-smoke, registers install.sh, seals manifest
  - Updates gateway.yaml case.dir + restarts gateway (one restart, ~5 min wait)

Agent checks (MCP over HTTPS):
  - tools/list → 18 core tools, zero add-on tools
  - case_status shows active case
  - run_command passes gate on sealed case
  - record_action + record_finding accepted
  - evidence_verify reports chain intact
  - F-A regression: corrupt evidence → gate blocks

Run from /home/sansforensics/sift-mcps/:
  python3 scripts/phase2_gate_test.py [--setup-only | --checks-only]

  --setup-only   Create case + seal + restart gateway (then wait for health)
  --checks-only  Skip setup; run agent checks against already-running gateway
  (default)      Do full setup + checks

Environment overrides:
  SIFT_PHASE2_GATE_CASE_ID  Case ID to use; default phase2-gate-smoke.
  SIFT_AGENT_TOKEN          Agent bearer token; default = first active role=agent token.
  SIFT_EXAMINER_TOKEN       Examiner bearer token; default = first active role=examiner token.
"""
from __future__ import annotations

import argparse
import http.client
import json
import os
import shutil
import ssl
import subprocess
import sys
import time
import urllib.request
from pathlib import Path
from typing import Any

# ── locate project ─────────────────────────────────────────────────────────
REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "packages/sift-core/src"))
sys.path.insert(0, str(REPO / "packages/sift-common/src"))
sys.path.insert(0, str(REPO / "packages/forensic-knowledge/src"))

# ── config ─────────────────────────────────────────────────────────────────
GW_HOST = "127.0.0.1"
GW_PORT = 4508
CA_CERT = Path.home() / ".sift/tls/ca-cert.pem"
GATEWAY_YAML = Path.home() / ".sift/gateway.yaml"
CASES_ROOT = Path("/cases")
CASE_ID = os.environ.get("SIFT_PHASE2_GATE_CASE_ID", "phase2-gate-smoke")
CASE_DIR = CASES_ROOT / CASE_ID
GATEWAY_START_TIMEOUT = 360  # uv run --project takes ~5 min

EXPECTED_CORE_TOOLS = {
    "run_command", "list_available_tools", "get_tool_help", "check_tools",
    "suggest_tools",
    "case_status", "case_file_structure", "query_case", "workflow_status",
    "evidence_list", "evidence_verify",
    "record_finding", "record_timeline_event", "list_existing_findings",
    "manage_todo",
    "log_reasoning", "record_action", "log_external_action",
    "environment_summary",  # gateway-native (registered in mcp_endpoint.py, not sift_core)
}


def _load_gateway_yaml() -> dict:
    import yaml as _yaml

    return _yaml.safe_load(GATEWAY_YAML.read_text()) or {}


def _gateway_api_keys() -> dict:
    return _load_gateway_yaml().get("api_keys") or {}


def _token_for_role(role: str) -> str:
    for token, meta in _gateway_api_keys().items():
        if isinstance(meta, dict) and meta.get("role") == role and not meta.get("revoked_at"):
            return token
    raise RuntimeError(f"No active {role!r} token found in {GATEWAY_YAML}")


AGENT_TOKEN = os.environ.get("SIFT_AGENT_TOKEN") or _token_for_role("agent")
EXAMINER_TOKEN = os.environ.get("SIFT_EXAMINER_TOKEN") or _token_for_role("examiner")

# ── results tracker ────────────────────────────────────────────────────────
results: list[tuple[str, bool, str]] = []
PASS, FAIL = "✓", "✗"


def check(label: str, ok: bool, detail: str = "") -> bool:
    icon = PASS if ok else FAIL
    d = (" [" + detail.replace("\n", " ")[:180] + "]") if detail else ""
    print(f"  {icon} {label}{d}")
    results.append((label, ok, detail))
    return ok


def section(title: str) -> None:
    print(f"\n── {title} ──")


# ── SSL / HTTP helpers ─────────────────────────────────────────────────────
def _ssl_ctx() -> ssl.SSLContext:
    ctx = ssl.create_default_context(cafile=str(CA_CERT) if CA_CERT.exists() else None)
    if not CA_CERT.exists():
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _parse_sse(raw: str) -> dict | None:
    for line in raw.splitlines():
        s = line.strip()
        if s.startswith("data:"):
            payload = s[5:].strip()
            if payload:
                try:
                    return json.loads(payload)
                except json.JSONDecodeError:
                    continue
    return None


def _post(path: str, body: bytes, hdrs: dict[str, str]) -> tuple[int, dict, str]:
    ctx = _ssl_ctx()
    conn = http.client.HTTPSConnection(GW_HOST, GW_PORT, context=ctx, timeout=30)
    try:
        conn.request("POST", path, body=body, headers=hdrs)
        r = conn.getresponse()
        resp_hdrs = {k.lower(): v for k, v in r.getheaders()}
        return r.status, resp_hdrs, r.read().decode("utf-8", errors="replace")
    finally:
        conn.close()


def _get(path: str, token: str) -> dict:
    ctx = _ssl_ctx()
    req = urllib.request.Request(
        f"https://{GW_HOST}:{GW_PORT}{path}",
        headers={"Authorization": f"Bearer {token}"},
    )
    try:
        with urllib.request.urlopen(req, context=ctx, timeout=10) as r:
            return json.loads(r.read())
    except Exception as e:
        return {"error": str(e)}


def _mcp_post(body: Any, token: str, session_id: str | None = None) -> tuple[dict, dict]:
    data = json.dumps(body).encode()
    hdrs: dict[str, str] = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
        "Accept": "application/json, text/event-stream",
    }
    if session_id:
        hdrs["Mcp-Session-Id"] = session_id
    code, resp_hdrs, raw = _post("/mcp/", data, hdrs)
    if code >= 400:
        return {"error": f"HTTP {code}: {raw[:400]}"}, resp_hdrs
    ct = resp_hdrs.get("content-type", "")
    if "text/event-stream" in ct:
        parsed = _parse_sse(raw)
        return (parsed if parsed else {"error": f"SSE parse fail: {raw[:200]}"}), resp_hdrs
    try:
        return json.loads(raw), resp_hdrs
    except json.JSONDecodeError:
        parsed = _parse_sse(raw)
        return (parsed if parsed else {"error": f"Non-JSON (ct={ct}): {raw[:200]}"}), resp_hdrs


def _init_session(token: str) -> str:
    body = {
        "jsonrpc": "2.0", "id": 1, "method": "initialize",
        "params": {
            "protocolVersion": "2024-11-05", "capabilities": {},
            "clientInfo": {"name": "phase2-gate-test", "version": "1.0"},
        },
    }
    _, hdrs = _mcp_post(body, token=token)
    sid = hdrs.get("mcp-session-id", "")
    if not sid:
        raise RuntimeError(f"No session ID. Headers: {hdrs}")
    _mcp_post({"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}},
              token=token, session_id=sid)
    return sid


def _tool(name: str, args: dict, sid: str, token: str = AGENT_TOKEN) -> str:
    resp, _ = _mcp_post(
        {"jsonrpc": "2.0", "id": 2, "method": "tools/call",
         "params": {"name": name, "arguments": args}},
        token=token, session_id=sid,
    )
    content = resp.get("result", {}).get("content", [])
    if not content and "error" in resp:
        return f"[MCP_ERROR] {resp['error']}"
    return " ".join(c.get("text", "") for c in content if isinstance(c, dict))


# ── setup helpers ──────────────────────────────────────────────────────────
def wait_for_gateway(timeout: int = GATEWAY_START_TIMEOUT) -> bool:
    deadline = time.time() + timeout
    dots = 0
    while time.time() < deadline:
        try:
            h = _get("/health", EXAMINER_TOKEN)
            if h.get("status") == "ok":
                print()
                return True
        except Exception:
            pass
        print(".", end="", flush=True)
        dots += 1
        if dots % 20 == 0:
            remaining = int(deadline - time.time())
            print(f" ({remaining}s left)")
        time.sleep(5)
    print()
    return False


def setup_case_and_restart() -> None:
    """Create case, seal evidence, update gateway.yaml, restart service."""
    from sift_core.case_ops import case_init_data
    from sift_core.approval_auth import derive_ledger_key
    from sift_core.evidence_chain import ChainStatus, chain_status, seal_manifest
    from sift_core.case_io import case_records_dir

    section("Setup: create case + seal evidence + configure gateway")
    gw = _load_gateway_yaml()
    examiner = str(gw.get("portal", {}).get("default_examiner") or os.environ.get("SIFT_EXAMINER") or "examiner")
    pw_path = Path("/var/lib/sift/passwords") / f"{examiner}.json"
    if not pw_path.exists():
        raise RuntimeError(f"Cannot derive portal ledger key; missing password entry: {pw_path}")
    pw_entry = json.loads(pw_path.read_text())
    ledger_key = derive_ledger_key(pw_entry["hash"])

    # Create case (remove if exists)
    CASES_ROOT.mkdir(parents=True, exist_ok=True)
    if CASE_DIR.exists():
        shutil.rmtree(CASE_DIR)
    records_dir = case_records_dir(CASE_DIR)
    if records_dir.exists():
        backup_dir = records_dir.parent / f"{records_dir.name}.pre-phase2-gate.{int(time.time())}"
        shutil.move(str(records_dir), str(backup_dir))
        print(f"  Backed up existing records dir: {backup_dir}")

    case_init_data(
        name="Phase 2 gate test",
        examiner=examiner,
        description="Phase 2 gate e2e test case",
        cases_dir=str(CASES_ROOT),
        case_id=CASE_ID,
    )
    print(f"  Created case: {CASE_DIR}")

    # Ensure records dir (F-B: outside case_root)
    case_records_dir(CASE_DIR).mkdir(parents=True, exist_ok=True)

    # Copy evidence file into case evidence dir
    ev_dir = CASE_DIR / "evidence"
    ev_dir.mkdir(parents=True, exist_ok=True)
    shutil.copy2(REPO / "install.sh", ev_dir / "install.sh")
    print(f"  Copied evidence: {ev_dir}/install.sh")

    # Seal
    manifest = seal_manifest(
        CASE_DIR,
        file_specs=[{"path": "evidence/install.sh", "description": "gate test evidence"}],
        examiner=examiner,
        derived_key=ledger_key,
    )
    print(f"  Sealed manifest v{manifest.get('version')}")

    # Verify
    cs = chain_status(CASE_DIR)
    assert cs.get("status") == ChainStatus.OK, f"chain_status not OK after seal: {cs}"
    print(f"  chain_status: OK ✓")

    # Update gateway.yaml
    import yaml as _yaml

    gw.setdefault("case", {})["dir"] = str(CASE_DIR)
    GATEWAY_YAML.write_text(_yaml.dump(gw, default_flow_style=False))
    print(f"  gateway.yaml case.dir → {CASE_DIR}")

    # Restart gateway
    print(f"  Restarting sift-gateway service...")
    subprocess.run(
        ["systemctl", "--user", "restart", "sift-gateway.service"],
        check=True, capture_output=True,
    )
    print(f"  Waiting for gateway health (up to {GATEWAY_START_TIMEOUT}s — uv run is slow)...")
    if not wait_for_gateway():
        raise RuntimeError(f"Gateway did not start within {GATEWAY_START_TIMEOUT}s")
    print(f"  Gateway healthy ✓")


# ════════════════════════════════════════════════════════════════════════════
# Agent checks
# ════════════════════════════════════════════════════════════════════════════
def _restore_and_reseal() -> None:
    """Restore evidence file from source and re-seal the manifest."""
    from sift_core.approval_auth import derive_ledger_key
    from sift_core.evidence_chain import chain_status, ChainStatus, seal_manifest
    gw = _load_gateway_yaml()
    examiner = str(gw.get("portal", {}).get("default_examiner") or os.environ.get("SIFT_EXAMINER") or "examiner")
    pw_entry = json.loads((Path("/var/lib/sift/passwords") / f"{examiner}.json").read_text())
    ledger_key = derive_ledger_key(pw_entry["hash"])
    ev_file = CASE_DIR / "evidence" / "install.sh"
    shutil.copy2(REPO / "install.sh", ev_file)
    seal_manifest(
        CASE_DIR,
        file_specs=[{"path": "evidence/install.sh", "description": "gate test evidence"}],
        examiner=examiner,
        derived_key=ledger_key,
    )
    cs = chain_status(CASE_DIR)
    if cs.get("status") != ChainStatus.OK:
        raise RuntimeError(f"Re-seal failed: {cs}")
    print("  Evidence restored and re-sealed ✓")


def run_checks() -> None:
    from sift_core.evidence_chain import chain_status, ChainStatus

    # ── Restore evidence if corrupted from a prior run ──────────────────
    cs = chain_status(CASE_DIR)
    if cs.get("status") != ChainStatus.OK:
        print(f"  NOTE: evidence corrupted from prior run ({cs.get('status')}), restoring...")
        _restore_and_reseal()
        # Give the gate cache time to notice the reseal (2s mtime window)
        time.sleep(3)

    # ── Health ────────────────────────────────────────────────────────────
    section("1. Gateway health")
    health = _get("/health", EXAMINER_TOKEN)
    check("status == ok", health.get("status") == "ok", str(health))

    # ── Initialize MCP session ────────────────────────────────────────────
    section("2. MCP initialize (agent token)")
    try:
        sid = _init_session(AGENT_TOKEN)
        check("agent session acquired", True, sid)
    except Exception as exc:
        check("agent session acquired (fatal)", False, str(exc))
        sys.exit(1)

    # ── tools/list ────────────────────────────────────────────────────────
    section("3. tools/list — 18 core tools, zero add-on tools")
    tl_resp, _ = _mcp_post(
        {"jsonrpc": "2.0", "id": 3, "method": "tools/list", "params": {}},
        token=AGENT_TOKEN, session_id=sid,
    )
    tools = tl_resp.get("result", {}).get("tools", [])
    tool_names = {t["name"] for t in tools}
    check("tools/list returned results", bool(tools), f"{len(tools)} tools")
    missing = EXPECTED_CORE_TOOLS - tool_names
    unexpected = {n for n in tool_names if n not in EXPECTED_CORE_TOOLS}
    check("all 18 core tools present", not missing,
          ("missing: " + ", ".join(sorted(missing))) if missing else
          f"all {len(EXPECTED_CORE_TOOLS)} present")
    check("no unexpected add-on tools", not unexpected,
          ("unexpected: " + ", ".join(sorted(unexpected))) if unexpected else "none")

    # ── case_status ───────────────────────────────────────────────────────
    section("4. case_status shows active case")
    cs_text = _tool("case_status", {}, sid)
    check("case_status returns case info",
          CASE_ID in cs_text or "finding" in cs_text.lower() or "evidence" in cs_text.lower(),
          cs_text[:300])

    # ── evidence_list ─────────────────────────────────────────────────────
    section("5. evidence_list shows registered evidence")
    ev_text = _tool("evidence_list", {}, sid)
    check("evidence_list returns evidence",
          "install.sh" in ev_text or "evidence" in ev_text.lower(),
          ev_text[:300])

    # ── run_command — gate passes on sealed case ──────────────────────────
    section("6. run_command passes gate (F-A — sealed evidence)")
    rc_text = _tool("run_command", {
        "command": ["echo", "phase2-gate-live"],
        "purpose": "Phase 2 gate: verify in-process executor after evidence seal",
    }, sid)
    check("run_command not blocked by gate",
          not any(kw in rc_text.lower() for kw in ("blocked", "chain", "seal")),
          rc_text[:200])
    check("run_command returned output",
          "phase2-gate-live" in rc_text or "stdout" in rc_text.lower(),
          rc_text[:200])

    # ── record_action (audit step) ────────────────────────────────────────
    section("7. record_action (audit/reasoning accepted)")
    ra_text = _tool("record_action", {
        "description": "Ran echo to confirm in-process executor works post-seal",
        "reasoning": "Phase 2 gate: sift_core execute pipeline live; F-A gate passes on sealed case.",
        "tool": "run_command",
        "command": "echo phase2-gate-live",
    }, sid)
    not_blocked = '"blocked"' not in ra_text
    check("record_action accepted (not blocked)",
          not_blocked and any(kw in ra_text.lower() for kw in ("record", "status", "ok", "timestamp", "written", "audit")),
          ra_text[:200])

    # ── record_finding ────────────────────────────────────────────────────
    section("8. record_finding with command provenance")
    rf_text = _tool("record_finding", {
        "finding": {
            "title": "Phase 2 gate: in-process executor confirmed",
            "description": (
                "echo command returned 'phase2-gate-live'. "
                "sift_core execute pipeline operational after evidence seal."
            ),
            "severity": "low",
            "category": "test",
        },
        "supporting_commands": [{
            "command": "echo phase2-gate-live",
            "purpose": "executor confirmation",
            "output": "phase2-gate-live",
        }],
    }, sid)
    rf_not_blocked = '"blocked"' not in rf_text
    check("record_finding accepted (not blocked, result returned)",
          rf_not_blocked and any(kw in rf_text.lower() for kw in
              ("draft", "status", "validation", "id", "creat", "written", "finding_id")),
          rf_text[:300])

    # ── evidence_verify (integrity check) ────────────────────────────────
    section("9. evidence_verify reports chain intact")
    ev2_text = _tool("evidence_verify", {}, sid)
    chain_ok = any(kw in ev2_text.lower() for kw in
                   ("ok", "valid", "intact", "pass", "no issues", "verified"))
    chain_broken = any(kw in ev2_text.lower() for kw in ("modified", "missing", "error", "tamper"))
    check("evidence_verify: no tampering detected",
          chain_ok and not chain_broken, ev2_text[:300])

    # ── F-A regression: corrupt evidence → gate blocks ────────────────────
    section("10. F-A regression: corrupt evidence → gate blocks run_command")
    ev_file = CASE_DIR / "evidence" / "install.sh"
    with ev_file.open("ab") as f:
        f.write(b"\n# corruption sentinel\n")
    time.sleep(2)  # let mtime-based cache expire

    rc_corrupt = _tool("run_command", {
        "command": ["echo", "should-be-blocked"],
        "purpose": "F-A regression: must block after corruption",
    }, sid)
    blocked = any(kw in rc_corrupt.lower() for kw in
                  ("blocked", "chain", "seal", "evidence", "modified", "tamper"))
    check("run_command blocked after corruption (F-A)", blocked, rc_corrupt[:300])
    _restore_and_reseal()
    time.sleep(3)

    # ── Portal rejects agent token ────────────────────────────────────────
    section("11. Portal rejects agent token (R-roles)")
    pr = _get("/portal/api/cases", AGENT_TOKEN)
    rejected = "error" in pr or "forbidden" in str(pr).lower() or "401" in str(pr) or "403" in str(pr)
    check("portal /portal/api/cases rejects agent token", rejected, str(pr)[:200])


# ── main ────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Phase 2 gate test")
    parser.add_argument("--setup-only", action="store_true")
    parser.add_argument("--checks-only", action="store_true")
    args = parser.parse_args()

    if not args.checks_only:
        setup_case_and_restart()
    if not args.setup_only:
        run_checks()

    section("Summary")
    passed = sum(1 for _, ok, _ in results if ok)
    total = len(results)
    print(f"\n  {passed}/{total} checks passed")
    failures = [(lbl, det) for lbl, ok, det in results if not ok]
    if failures:
        print("\n  FAILURES:")
        for lbl, det in failures:
            print(f"    {FAIL} {lbl}")
            if det:
                print(f"         {det[:400]}")
        sys.exit(1)
    else:
        print("\n  Phase 2 GATE: ALL CHECKS PASSED ✓")
        sys.exit(0)
