#!/usr/bin/env python3
"""Conformance probe script for Sift backends.

Validates that add-on backends adhere to Namespace prefixing, manifest validation,
health checks, and tool contract invariants.
"""

import argparse
import json
import os
import ssl
import sys
import http.client
import urllib.request
from pathlib import Path
import jsonschema

# Locate repo root
REPO_ROOT = Path(__file__).resolve().parent.parent

# SSL context helper
def get_ssl_context():
    ca_cert = Path.home() / ".sift/tls/ca-cert.pem"
    ctx = ssl.create_default_context(cafile=str(ca_cert) if ca_cert.exists() else None)
    if not ca_cert.exists():
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    return ctx

def _load_gateway_yaml() -> dict:
    gateway_yaml = Path.home() / ".sift/gateway.yaml"
    if not gateway_yaml.exists():
        return {}
    import yaml as _yaml
    try:
        return _yaml.safe_load(gateway_yaml.read_text()) or {}
    except Exception:
        return {}

def _token_for_role(role: str) -> str:
    api_keys = _load_gateway_yaml().get("api_keys") or {}
    for token, meta in api_keys.items():
        if isinstance(meta, dict) and meta.get("role") == role and not meta.get("revoked_at"):
            return token
    # Default fallback to any key
    if api_keys:
        return list(api_keys.keys())[0]
    return ""

def get_gateway_url() -> str:
    config = _load_gateway_yaml()
    gw = config.get("gateway", {})
    if isinstance(gw, dict):
        port = gw.get("port", 4508)
        tls = gw.get("tls", {})
        scheme = "https" if isinstance(tls, dict) and tls.get("certfile") else "http"
        return f"{scheme}://127.0.0.1:{port}"
    return "http://127.0.0.1:4508"

def make_gateway_request(url, path, method, params, token, session_id=None):
    from urllib.parse import urlparse
    parsed = urlparse(url)
    is_https = parsed.scheme == "https"
    host = parsed.hostname or "127.0.0.1"
    port = parsed.port or (443 if is_https else 80)
    
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
        "Accept": "application/json, text/event-stream",
    }
    if session_id:
        headers["Mcp-Session-Id"] = session_id
        
    body = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": method,
        "params": params
    }
    
    body_data = json.dumps(body).encode("utf-8")
    
    if is_https:
        conn = http.client.HTTPSConnection(host, port, context=get_ssl_context(), timeout=15)
    else:
        conn = http.client.HTTPConnection(host, port, timeout=15)
        
    try:
        conn.request("POST", path, body=body_data, headers=headers)
        r = conn.getresponse()
        resp_headers = {k.lower(): v for k, v in r.getheaders()}
        status = r.status
        content = r.read().decode("utf-8", errors="replace")
        return status, resp_headers, content
    except Exception as e:
        return 500, {}, str(e)
    finally:
        conn.close()

def get_gateway_health_status(url, token):
    from urllib.parse import urlparse
    parsed = urlparse(url)
    is_https = parsed.scheme == "https"
    host = parsed.hostname or "127.0.0.1"
    port = parsed.port or (443 if is_https else 80)
    
    headers = {
        "Authorization": f"Bearer {token}",
    }
    if is_https:
        conn = http.client.HTTPSConnection(host, port, context=get_ssl_context(), timeout=10)
    else:
        conn = http.client.HTTPConnection(host, port, timeout=10)
        
    try:
        conn.request("GET", "/health", headers=headers)
        r = conn.getresponse()
        status = r.status
        content = r.read().decode("utf-8", errors="replace")
        return status, content
    except Exception as e:
        return 500, str(e)
    finally:
        conn.close()

def get_gateway_services_status(url, token):
    from urllib.parse import urlparse
    parsed = urlparse(url)
    is_https = parsed.scheme == "https"
    host = parsed.hostname or "127.0.0.1"
    port = parsed.port or (443 if is_https else 80)
    
    headers = {
        "Authorization": f"Bearer {token}",
    }
    if is_https:
        conn = http.client.HTTPSConnection(host, port, context=get_ssl_context(), timeout=10)
    else:
        conn = http.client.HTTPConnection(host, port, timeout=10)
        
    try:
        conn.request("GET", "/api/v1/services", headers=headers)
        r = conn.getresponse()
        status = r.status
        content = r.read().decode("utf-8", errors="replace")
        return status, content
    except Exception as e:
        return 500, str(e)
    finally:
        conn.close()

def run_mcp_handshake(gateway_url, backend_name, token):
    # Step 1: initialize
    path = f"/mcp/{backend_name}"
    init_params = {
        "protocolVersion": "2024-11-05",
        "capabilities": {},
        "clientInfo": {"name": "conformance-probe", "version": "1.0"}
    }
    status, headers, content = make_gateway_request(
        gateway_url, path, "initialize", init_params, token
    )
    if status >= 400:
        return None, f"Failed to initialize: HTTP {status} - {content}"
        
    session_id = headers.get("mcp-session-id")
    
    # Step 2: tools/list
    status, headers, content = make_gateway_request(
        gateway_url, path, "tools/list", {}, token, session_id=session_id
    )
    if status >= 400:
        return None, f"Failed to list tools: HTTP {status} - {content}"
        
    try:
        data = json.loads(content)
        if "error" in data:
            return None, f"JSON-RPC Error listing tools: {data['error']}"
        tools = data.get("result", {}).get("tools", [])
        return tools, None
    except json.JSONDecodeError:
        return None, f"Invalid JSON returned from tools/list: {content}"

def validate_backend(manifest_path, schema, gateway_url, token, skip_mcp_check=False):
    print(f"Validating manifest: {manifest_path}")
    try:
        with open(manifest_path, "r", encoding="utf-8") as f:
            manifest = json.load(f)
    except Exception as e:
        print(f"  [FAIL] Failed to read/parse JSON: {e}")
        return False

    # spec_version checks
    spec_version = manifest.get("spec_version", "")
    if not isinstance(spec_version, str) or not spec_version.startswith("1."):
        print(f"  [FAIL] Unsupported spec_version: {spec_version}. Gateway only supports 1.x.")
        return False

    # Schema validation
    try:
        jsonschema.validate(instance=manifest, schema=schema)
        print("  [PASS] JSON schema validation passed.")
    except Exception as e:
        print(f"  [FAIL] JSON schema validation failed: {e}")
        return False

    name = manifest.get("name")
    namespace = manifest.get("namespace", "")

    # MCP check (only if gateway is running and check is not skipped)
    if not skip_mcp_check:
        print(f"  Connecting to gateway per-backend mount: /mcp/{name}")
        tools, err = run_mcp_handshake(gateway_url, name, token)
        if err:
            print(f"  [FAIL] MCP communication failure: {err}")
            return False
            
        print(f"  [PASS] Successfully retrieved tools list ({len(tools)} tools).")
        
        # Tools invariants validation
        declared_tools = {t["name"] for t in manifest.get("tools", [])}
        
        for tool in tools:
            tool_name = tool.get("name", "")
            
            # Prefix check
            if namespace and not tool_name.startswith(f"{namespace}_"):
                print(f"  [FAIL] Tool '{tool_name}' does not start with declared namespace prefix '{namespace}_'")
                return False
                
            # Declared in manifest check
            if tool_name not in declared_tools:
                print(f"  [FAIL] Tool '{tool_name}' is not declared in the manifest 'tools' block")
                return False
                
            # Identity argument check
            input_schema = tool.get("inputSchema", {})
            properties = input_schema.get("properties", {})
            for forbidden in ("analyst_override", "analyst_identity", "override_examiner"):
                if forbidden in properties:
                    print(f"  [FAIL] Tool '{tool_name}' schema contains forbidden identity/override argument '{forbidden}'")
                    return False
                    
        print("  [PASS] All advertised tools are correctly prefixed and declared.")
        print("  [PASS] No identity/override arguments found in tool schemas.")
        
        # Health check validation
        print("  Checking backend health status via gateway...")
        status_code, services_content = get_gateway_services_status(gateway_url, token)
        if status_code == 200:
            try:
                services = json.loads(services_content)
                bk_status = services.get("services", {}).get(name, {})
                health = bk_status.get("health", {})
                if health.get("status") == "ok":
                    print("  [PASS] Backend health is 'ok' via gateway.")
                else:
                    print(f"  [WARNING] Backend health is not 'ok' (status: {health.get('status')})")
            except Exception as e:
                print(f"  [WARNING] Failed to parse services endpoint response: {e}")
        else:
            print(f"  [WARNING] Gateway /api/v1/services returned status {status_code}")
            
    return True

def main():
    parser = argparse.ArgumentParser(
        description="SIFT Backend Conformance Probe"
    )
    parser.add_argument(
        "--manifest-dir",
        default=str(REPO_ROOT / "packages"),
        help="Directory to scan for sift-backend.json files recursively",
    )
    parser.add_argument(
        "--manifest",
        default=None,
        help="Path to a single sift-backend.json manifest file",
    )
    parser.add_argument(
        "--gateway-url",
        default=None,
        help="SIFT Gateway base URL (defaults to ~/.sift/gateway.yaml or http://127.0.0.1:4508)",
    )
    parser.add_argument(
        "--token",
        default=None,
        help="Bearer auth token (defaults to SIFT_SERVICE_TOKEN env var or ~/.sift/gateway.yaml)",
    )
    parser.add_argument(
        "--skip-mcp",
        action="store_true",
        help="Skip MCP/gateway integration checks and only perform schema validation",
    )
    args = parser.parse_args()

    # Load schema
    schema_path = REPO_ROOT / "packages/sift-gateway/src/sift_gateway/sift-backend.schema.json"
    if not schema_path.exists():
        print(f"ERROR: schema file not found at {schema_path}", file=sys.stderr)
        sys.exit(1)
        
    with open(schema_path, "r", encoding="utf-8") as f:
        schema = json.load(f)

    # Determine gateway URL and token
    gateway_url = args.gateway_url or get_gateway_url()
    token = args.token or os.environ.get("SIFT_SERVICE_TOKEN") or _token_for_role("agent") or _token_for_role("examiner")
    
    if not args.skip_mcp and not token:
        print("WARNING: No bearer token found or provided. MCP integration checks might fail if authentication is enabled.", file=sys.stderr)

    # Find manifests
    if args.manifest:
        manifest_files = [Path(args.manifest)]
    else:
        manifest_files = list(Path(args.manifest_dir).glob("**/sift-backend.json"))

    if not manifest_files:
        print("No sift-backend.json manifests found.")
        sys.exit(0)

    print(f"Found {len(manifest_files)} backend manifest(s) to validate.")
    all_ok = True
    for fpath in manifest_files:
        if not validate_backend(fpath, schema, gateway_url, token, skip_mcp_check=args.skip_mcp):
            all_ok = False
            
    if all_ok:
        print("\nAll backends conform to the Sift contract!")
        sys.exit(0)
    else:
        print("\nSome backends failed conformance validation.")
        sys.exit(1)

if __name__ == "__main__":
    main()
